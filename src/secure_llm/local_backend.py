"""Local Hugging Face Transformers backend and tolerant structured output parsing."""
from __future__ import annotations

import json
import gc
import random
import re
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class StructuredAction:
    name: str
    arguments: dict[str, Any]


@dataclass
class StructuredResult:
    response: str = ""
    action: StructuredAction | None = None
    valid_json: bool = False
    parse_error: str | None = None
    invalid_action_schema: str | None = None
    extracted_json: dict[str, Any] | None = None


@dataclass
class LocalGeneration:
    model_id: str
    raw_output: str
    structured: StructuredResult
    latency_ms: float
    input_tokens: int
    generation_tokens: int
    gpu_memory_allocated_mb: float
    generation_config: dict[str, Any] = field(default_factory=dict)


def extract_first_json(text: str) -> tuple[dict[str, Any] | None, str | None]:
    """Extract the first decodable JSON object despite fences or surrounding text."""
    cleaned = re.sub(r"```(?:json)?", "", text, flags=re.IGNORECASE).replace("```", "")
    decoder = json.JSONDecoder()
    errors: list[str] = []
    for index, char in enumerate(cleaned):
        if char != "{":
            continue
        try:
            value, _ = decoder.raw_decode(cleaned[index:])
            if isinstance(value, dict):
                return value, None
        except json.JSONDecodeError as exc:
            errors.append(f"column {exc.colno}: {exc.msg}")
    return None, "no valid JSON object found" + (f" ({errors[-1]})" if errors else "")


def parse_structured_output(text: str) -> StructuredResult:
    value, error = extract_first_json(text)
    if value is None:
        return StructuredResult(parse_error=error)
    response = value.get("response")
    if not isinstance(response, str):
        return StructuredResult(valid_json=True, parse_error=None, invalid_action_schema="response must be a string", extracted_json=value)
    action = value.get("action")
    if action is None:
        return StructuredResult(response=response, valid_json=True, extracted_json=value)
    if not isinstance(action, dict):
        return StructuredResult(response=response, valid_json=True, invalid_action_schema="action must be an object or null", extracted_json=value)
    name, arguments = action.get("name"), action.get("arguments")
    if not isinstance(name, str) or not name:
        return StructuredResult(response=response, valid_json=True, invalid_action_schema="action.name must be a non-empty string", extracted_json=value)
    if not isinstance(arguments, dict):
        return StructuredResult(response=response, valid_json=True, invalid_action_schema="action.arguments must be an object", extracted_json=value)
    return StructuredResult(response=response, action=StructuredAction(name, arguments), valid_json=True, extracted_json=value)


class LocalTransformersBackend:
    def __init__(self, model_id: str, device: str = "auto", dtype: str = "auto", quantization: str | None = None) -> None:
        self.model_id = model_id
        self.device = device
        self.dtype = dtype
        self.quantization = quantization
        self.tokenizer: Any = None
        self.model: Any = None
        self.torch: Any = None

    def load(self) -> None:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        self.torch = torch
        kwargs: dict[str, Any] = {"torch_dtype":"auto", "low_cpu_mem_usage":True}
        if self.device == "auto" and torch.cuda.is_available():
            kwargs["device_map"] = "auto"
        elif self.device not in {"auto", "cpu"}:
            kwargs["device_map"] = self.device
        if self.quantization:
            if self.quantization not in {"4bit", "8bit"}:
                raise ValueError("quantization must be null, 4bit, or 8bit")
            kwargs["load_in_4bit" if self.quantization == "4bit" else "load_in_8bit"] = True
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_id)
        self.model = AutoModelForCausalLM.from_pretrained(self.model_id, **kwargs)
        if "device_map" not in kwargs:
            target = "cuda" if self.device == "auto" and torch.cuda.is_available() else self.device if self.device != "auto" else "cpu"
            self.model.to(target)
        self.model.eval()
        if self.tokenizer.pad_token_id is None:
            self.tokenizer.pad_token_id = self.tokenizer.eos_token_id

    def unload(self) -> None:
        if self.model is not None:
            del self.model
        if self.tokenizer is not None:
            del self.tokenizer
        self.model = self.tokenizer = None
        gc.collect()
        if self.torch is not None and self.torch.cuda.is_available():
            self.torch.cuda.empty_cache()

    def generate(self, messages: list[dict[str, str]], *, temperature: float, top_p: float, max_new_tokens: int, seed: int, do_sample: bool = False, stop_on_complete_json: bool = False) -> LocalGeneration:
        if self.model is None or self.tokenizer is None:
            raise RuntimeError("model is not loaded")
        torch = self.torch
        random.seed(seed);torch.manual_seed(seed)
        if torch.cuda.is_available():torch.cuda.manual_seed_all(seed);torch.cuda.reset_peak_memory_stats()
        rendered = self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = self.tokenizer(rendered, return_tensors="pt")
        device = next(self.model.parameters()).device
        inputs = {key:value.to(device) for key,value in inputs.items()}
        kwargs: dict[str, Any] = {"max_new_tokens":max_new_tokens,"do_sample":do_sample,"pad_token_id":self.tokenizer.pad_token_id,"eos_token_id":self.tokenizer.eos_token_id}
        if stop_on_complete_json:
            from transformers import StoppingCriteria,StoppingCriteriaList
            tokenizer=self.tokenizer;prompt_length=int(inputs["input_ids"].shape[1])
            class CompleteJson(StoppingCriteria):
                def __call__(self,input_ids,scores,**unused):
                    generated=tokenizer.decode(input_ids[0,prompt_length:],skip_special_tokens=True)
                    decoder=json.JSONDecoder()
                    pos=generated.find("{")
                    if pos>=0:
                        try:decoder.raw_decode(generated[pos:]);return True
                        except json.JSONDecodeError:pass
                    return False
            kwargs["stopping_criteria"]=StoppingCriteriaList([CompleteJson()])
        if do_sample:
            kwargs.update({"temperature":temperature,"top_p":top_p})
        start=time.perf_counter()
        with torch.inference_mode():output=self.model.generate(**inputs,**kwargs)
        latency=(time.perf_counter()-start)*1000;new_tokens=output[0,inputs["input_ids"].shape[1]:];raw=self.tokenizer.decode(new_tokens,skip_special_tokens=True)
        gpu_mb=torch.cuda.max_memory_allocated()/1024**2 if torch.cuda.is_available() else 0.0
        return LocalGeneration(self.model_id,raw,parse_structured_output(raw),round(latency,2),int(inputs["input_ids"].shape[1]),int(new_tokens.shape[0]),round(gpu_mb,2),{"temperature":temperature,"top_p":top_p,"do_sample":do_sample,"max_new_tokens":max_new_tokens,"stop_on_complete_json":stop_on_complete_json,"seed":seed,"device":str(device),"dtype":str(next(self.model.parameters()).dtype),"quantization":self.quantization})
