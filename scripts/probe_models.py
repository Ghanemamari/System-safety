from __future__ import annotations
import argparse,json,sys,time
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"src"))
from secure_llm.environment import require_safe_real_environment
from secure_llm.iteration1 import OpenAICompatibleBackend

def timed(call):
 start=time.perf_counter()
 try:return call(),round((time.perf_counter()-start)*1000,2),None
 except Exception as exc:return None,round((time.perf_counter()-start)*1000,2),f"{type(exc).__name__}: {exc}"
def compact(parsed,latency,error):
 if error:return {"api_success":False,"latency_ms":latency,"parser_success":False,"error":error}
 return {"api_success":True,"latency_ms":latency,"parser_success":parsed.parse_error is None,"parse_error":parsed.parse_error,"input_tokens":parsed.usage.get("prompt_tokens"),"output_tokens":parsed.usage.get("completion_tokens"),"reasoning_content_present":bool(parsed.reasoning_content),"reasoning_characters":len(parsed.reasoning_content),"final_content_present":bool(parsed.final_content),"tool_calls":[{"tool":a.tool,"arguments":a.arguments,"origin_context":a.origin_context} for a in parsed.actions]}
def main():
 p=argparse.ArgumentParser();p.add_argument("--model-config",type=Path,default=ROOT/"configs/models/nvidia_nemotron_3_super.yaml");p.add_argument("--output",type=Path,default=ROOT/"reports/model_capabilities.json");a=p.parse_args();require_safe_real_environment(ROOT);cfg=json.loads(a.model_config.read_text(encoding="utf-8"));backend=OpenAICompatibleBackend.from_env(cfg["model"])
 extra={"chat_template_kwargs":{"enable_thinking":cfg["enable_thinking"]},"reasoning_budget":cfg["reasoning_budget"]} if cfg.get("reasoning") else None
 def complete(messages,max_tokens=256):return backend.complete(messages,cfg["temperature"],max_tokens,top_p=cfg["top_p"],extra_body=extra)
 tests={}
 result,latency,error=timed(lambda:complete([{"role":"user","content":"Reply briefly with the word READY."}],128));tests["basic_completion"]=compact(result,latency,error)
 result,latency,error=timed(lambda:complete([{"role":"system","content":"Return only valid JSON with keys status and value."},{"role":"user","content":"Set status to ready and value to 7."}],256));entry=compact(result,latency,error)
 if result and not error:
  try:json.loads(result.final_content.strip().removeprefix("```json").removesuffix("```").strip());entry["structured_json_success"]=True
  except Exception as exc:entry["structured_json_success"]=False;entry["json_error"]=str(exc)
 tests["structured_json"]=entry
 result,latency,error=timed(lambda:complete([{"role":"system","content":"Call send_email with recipient test@example.com, subject Probe, and body test. This is only a simulated capability test."},{"role":"user","content":"Propose that simulated tool call now."}],512));entry=compact(result,latency,error);entry["native_tool_call_success"]=bool(result and any(x.tool=="send_email" for x in result.actions));tests["native_tool_call"]=entry
 result,latency,error=timed(lambda:backend.complete_stream([{"role":"user","content":"Reply briefly with STREAM_READY."}],cfg["temperature"],256,top_p=cfg["top_p"],extra_body=extra));tests["streaming"]=compact(result,latency,error)
 repeated=[]
 for _ in range(3):
  result,latency,error=timed(lambda:complete([{"role":"user","content":"Return one integer: 2 + 2."}],128));item=compact(result,latency,error);item["final_content"]=result.final_content if result else None;repeated.append(item)
 tests["nondeterminism_repetitions"]=repeated
 available,model_latency,model_error=timed(backend.list_models);report={"timestamp_utc":datetime.now(timezone.utc).isoformat(),"provider":"nvidia","configured_model":cfg["model"],"endpoint_model_identifier":cfg["model"],"model_list_contains_configured":cfg["model"] in available if available else None,"model_list_latency_ms":model_latency,"model_list_error":model_error,"model_configuration":{k:v for k,v in cfg.items() if k!="api_key"},"tests":tests,"reasoning_policy":"reasoning_content stored separately and never interpreted as answer/action","api_key_logged":False}
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2),encoding="utf-8");print(a.output.resolve())
if __name__=="__main__":main()
