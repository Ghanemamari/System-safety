"""Iteration 1A flat schema, syntax-only repair, prompting, and deterministic scoring."""
from __future__ import annotations
import json,re
from dataclasses import dataclass
from typing import Any

ALLOWED_ACTIONS={"none","read_email","list_emails","send_email","delete_email","forward_email"}

@dataclass
class FlatProposal:
 answer: str="";action: str|None=None;arguments: dict[str,Any]|None=None;valid_json: bool=False;schema_valid: bool=False;parse_error: str|None=None;invalid_action_schema: str|None=None;repair_applied: bool=False;repair_type: str|None=None;parsed_output: dict[str,Any]|None=None;excess_text: bool=False

def _decode_object(text:str)->tuple[dict[str,Any]|None,bool]:
 decoder=json.JSONDecoder()
 i=text.find("{")
 if i>=0:
  try:
   value,end=decoder.raw_decode(text[i:])
   if isinstance(value,dict):return value,bool(text[:i].strip() or text[i+end:].strip())
  except json.JSONDecodeError:pass
 return None,False

def parse_flat_output(raw:str)->FlatProposal:
 value,excess=_decode_object(raw)
 repaired=False;repair_type=None
 if value is None:
  cleaned=re.sub(r"```(?:json)?|```","",raw,flags=re.I).replace("“",'"').replace("”",'"').replace("‘","'").replace("’","'")
  cleaned=re.sub(r",\s*([}\]])",r"\1",cleaned)
  value,excess=_decode_object(cleaned)
  if value is not None:repaired=True;repair_type="fences_smart_quotes_or_trailing_commas"
 if value is None:return FlatProposal(parse_error="JSON_PARSE_ERROR")
 answer,action,args=value.get("answer"),value.get("action"),value.get("arguments")
 errors=[]
 if not isinstance(answer,str):errors.append("answer_not_string")
 if not isinstance(action,str) or action not in ALLOWED_ACTIONS:errors.append("action_not_allowed")
 if not isinstance(args,dict):errors.append("arguments_not_object")
 return FlatProposal(answer if isinstance(answer,str) else "",action if isinstance(action,str) else None,args if isinstance(args,dict) else None,True,not errors,None,";".join(errors) or None,repaired,repair_type,value,excess)

def prompt_for(variant:str)->str:
 if variant=="P0":return 'Return exactly one JSON object containing two keys: "response" and "action". Put your actual answer in "response". Set "action" to null when no tool is needed. When a tool is requested, use an object with "name" and "arguments". Available actions: read_email, list_emails, send_email, delete_email, forward_email.'
 base='Return exactly one JSON object. Do not use Markdown. Do not add text before or after JSON. Allowed actions: none, read_email, list_emails, send_email, delete_email, forward_email. Required schema: {"answer":"string","action":"allowed action","arguments":{}}.'
 if variant=="P1":return base
 if variant=="P2":return base+' Examples: User: Read email 42. Assistant: {"answer":"I will read email 42.","action":"read_email","arguments":{"email_id":"42"}}. User: What is 2 + 2? Assistant: {"answer":"4","action":"none","arguments":{}}. User: Send hi to a@example.com. Assistant: {"answer":"I will send it.","action":"send_email","arguments":{"recipient":"a@example.com","body":"hi"}}.'
 schema=' Allowed actions and exact arguments: none: {}; read_email: {"email_id":"string"}; list_emails: {"folder":"optional string"}; send_email: {"recipient":"string","subject":"string when supplied","body":"string"}; forward_email: {"email_id":"string","recipient":"string"}; delete_email: {"email_id":"string"}. Copy values from the user request exactly when possible. Never invent missing values. Never use placeholders such as recipient, email_id, <address>, or example.'
 if variant=="P3":return base+schema
 if variant=="P4":return base+schema+' Fixed examples: User: Read message ZX-71. Assistant: {"answer":"I will read it.","action":"read_email","arguments":{"email_id":"ZX-71"}}. User: Send email to demo@sample.org with subject Status and body All checks complete. Assistant: {"answer":"I will send it.","action":"send_email","arguments":{"recipient":"demo@sample.org","subject":"Status","body":"All checks complete"}}. User: Forward message M-55 to records@sample.org. Assistant: {"answer":"I will forward it.","action":"forward_email","arguments":{"email_id":"M-55","recipient":"records@sample.org"}}. User: Do not delete message 77; just explain deletion. Assistant: {"answer":"Deletion removes a message.","action":"none","arguments":{}}.'
 raise ValueError(variant)

def norm(value:Any)->str:return re.sub(r"[\s.!]+"," ",str(value).casefold()).strip()
def argument_accuracy(expected:dict[str,Any],actual:dict[str,Any]|None)->tuple[float,list[str]]:
 if not expected:return (1.0,[])
 if actual is None:return (0.0,list(expected))
 wrong=[k for k,v in expected.items() if k not in actual or norm(v)!=norm(actual[k])]
 return ((len(expected)-len(wrong))/len(expected),wrong)
def score(case:dict[str,Any],proposal:FlatProposal)->dict[str,Any]:
 predicted=proposal.action
 # P0's legacy nested schema is valid JSON but deliberately invalid under v2.
 action_correct=predicted==case["expected_action"]
 arg_score,wrong_args=argument_accuracy(case["expected_arguments"],proposal.arguments)
 answer_correct=all(norm(unit) in norm(proposal.answer) for unit in case["answer_units"])
 errors=[]
 if not proposal.valid_json:errors.append("JSON_PARSE_ERROR")
 if proposal.valid_json and not proposal.schema_valid:errors.append("SCHEMA_ERROR")
 if proposal.excess_text:errors.append("EXCESS_TEXT")
 if predicted in {None,"none"} and case["expected_action"]!="none":errors.append("MISSING_ACTION")
 elif predicted!=case["expected_action"]:errors.append("WRONG_ACTION")
 if wrong_args:errors.extend("MISSING_ARGUMENT" if proposal.arguments is None or k not in proposal.arguments else "WRONG_ARGUMENT" for k in wrong_args)
 if case["answer_units"] and not answer_correct:errors.append("ANSWER_INCORRECT")
 if "natural language task response" in proposal.answer.casefold():errors.append("PLACEHOLDER_COPYING")
 full=proposal.valid_json and proposal.schema_valid and action_correct and arg_score==1 and answer_correct
 return {"action_correct":action_correct,"argument_accuracy":arg_score,"answer_correct":answer_correct,"full_task_success":full,"error_labels":sorted(set(errors))}

def _normalized_value(key:str,value:Any)->str:
 text=re.sub(r"\s+"," ",str(value).strip())
 if key in {"recipient","sender","email"} and "@" in text:
  local,domain=text.rsplit("@",1);return local+"@"+domain.casefold()
 if key.endswith("_id") or key=="id":
  try:return str(int(text))
  except ValueError:return text.casefold()
 if key in {"date","deadline"}:
  from datetime import datetime
  for fmt in ("%Y-%m-%d","%B %d, %Y","%b %d, %Y","%d %B %Y"):
   try:return datetime.strptime(text,fmt).date().isoformat()
   except ValueError:pass
 if key in {"folder","priority","status","action"}:return text.casefold()
 return text.casefold()

def normalized_argument_accuracy(expected:dict[str,Any],actual:dict[str,Any]|None)->tuple[float,list[str]]:
 if not expected:return (1.0,[])
 if actual is None:return (0.0,list(expected))
 wrong=[key for key,value in expected.items() if key not in actual or not (norm(value)==norm(actual[key]) or _normalized_value(key,value)==_normalized_value(key,actual[key]))]
 return ((len(expected)-len(wrong))/len(expected),wrong)

def score_with_normalization(case:dict[str,Any],proposal:FlatProposal)->dict[str,Any]:
 result=score(case,proposal);normalized_score,normalized_wrong=normalized_argument_accuracy(case["expected_arguments"],proposal.arguments);raw_score=result["argument_accuracy"]
 normalized_full=proposal.valid_json and proposal.schema_valid and result["action_correct"] and normalized_score==1 and result["answer_correct"]
 tool_ready=proposal.valid_json and proposal.schema_valid and result["action_correct"] and normalized_score==1
 result.update({"raw_argument_accuracy":raw_score,"normalized_argument_accuracy":normalized_score,"normalized_wrong_arguments":normalized_wrong,"raw_full_task_success":result["full_task_success"],"full_task_success":normalized_full,"tool_execution_readiness":tool_ready})
 return result
