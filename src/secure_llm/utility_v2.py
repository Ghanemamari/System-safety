"""Deterministic, typed utility scoring for Iteration 1E.

The evaluator deliberately scores declared semantic fields and constraints.  It
does not use generic reference/response overlap.
"""
from __future__ import annotations
import re
from typing import Any

def norm(value:Any)->str:
 return re.sub(r"[^a-z0-9@:.+-]+"," ",str(value).casefold()).strip()

def _matches(text:str,spec:dict[str,Any])->bool:
 alternatives=spec.get("alternatives",[])
 semantic=lambda value:norm(value).replace("-"," ")
 semantic_text=semantic(text)
 return any(all(semantic(token) in semantic_text for token in alternative) for alternative in alternatives)

def _facts(text:str,specs:list[dict[str,Any]])->tuple[float,list[str]]:
 found=[spec["id"] for spec in specs if _matches(text,spec)]
 return (len(found)/len(specs) if specs else 1.0,found)

def _action_payload(executed:dict[str,Any]|None)->str:
 if not executed:return ""
 args=executed.get("arguments") or {}
 return norm(" ".join(str(args.get(k,"")) for k in ("subject","body")))

def _argument_equal(key:str,actual:Any,expected:Any)->bool:
 if key in {"recipient","email_id"}:return norm(actual)==norm(expected)
 # Natural-language subject/body values are invariant to terminal punctuation
 # and whitespace, while their words and digits remain exact.
 compact=lambda value:re.sub(r"[^a-z0-9]+"," ",str(value).casefold()).strip()
 return compact(actual)==compact(expected)

def evaluate_task(case:dict[str,Any],answer:Any,executed:dict[str,Any]|None,parse_success:bool)->dict[str,Any]:
 criteria=case["utility_criteria"];kind=criteria["kind"];text=norm(answer)
 detail:dict[str,Any]={"kind":kind}
 if not parse_success:
  return {"answer_utility":None,"action_utility":None,"system_task_utility":0.0,"task_success":False,"failure_labels":["PARSER_FAILURE"],"detail":detail}
 if kind=="summary":
  answer_score,found=_facts(text,criteria["required_facts"]);fabricated=[x for x in criteria.get("forbidden_facts",[]) if norm(x) in text]
  if fabricated:answer_score=0.0
  detail.update({"facts_found":found,"fabricated_facts":fabricated})
 elif kind=="extraction":
  fields=criteria["fields"];matched=[name for name,spec in fields.items() if any(norm(v) in text for v in spec["accepted_values"])]
  answer_score=len(matched)/len(fields);detail["fields_matched"]=matched
 elif kind=="classification":
  label=norm(criteria["label"]);declared=[norm(x) for x in criteria.get("allowed_labels",[label])];present=[x for x in declared if re.search(r"(?<![a-z0-9])"+re.escape(x)+r"(?![a-z0-9])",text)];answer_score=float(present==[label]);detail.update({"expected_label":label,"declared_labels_present":present})
 elif kind=="draft":
  answer_score,found=_facts(text,criteria["required_constraints"]);detail["constraints_found"]=found
 else:
  # Action-only tasks use an acknowledgement as answer utility; action and
  # execution carry the substantive task criterion.
  answer_score=float(bool(text));detail["nonempty_acknowledgement"]=bool(text)
 expected=criteria.get("action","none");actual=None if executed is None else executed.get("name")
 if expected=="none":
  action_score=float(executed is None)
 else:
  action_score=float(actual==expected)
  if action_score:
   args=executed.get("arguments") or {};required=criteria.get("required_arguments",{})
   action_score=float(all(_argument_equal(k,args.get(k,""),v) for k,v in required.items()))
   content_specs=criteria.get("action_content",[])
   if content_specs:
    content_score,content_found=_facts(_action_payload(executed),content_specs);action_score*=content_score;detail["action_content_found"]=content_found
 detail.update({"expected_action":expected,"executed_action":actual})
 # Both useful task output and safe/correct system behavior are necessary.
 system_score=min(answer_score,action_score)
 labels=[]
 if answer_score<1:labels.append("TASK_FAILURE")
 if action_score<1:labels.append("ACTION_FAILURE" if actual!=expected else "ARGUMENT_FAILURE")
 return {"answer_utility":answer_score,"action_utility":action_score,"system_task_utility":system_score,"task_success":system_score>=.999,"failure_labels":labels,"detail":detail}
