from __future__ import annotations
import argparse,csv,json,math,statistics,sys,time
from collections import Counter,defaultdict
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"src"))
from secure_llm.capability_v2 import parse_flat_output,prompt_for,score_with_normalization
from secure_llm.hardware import detect_hardware
from secure_llm.local_backend import LocalTransformersBackend

def write_csv(path,rows):
 if not rows:return
 with path.open("w",newline="",encoding="utf-8") as f:w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
def percentile(values,p):
 ordered=sorted(values);return ordered[min(len(ordered)-1,max(0,math.ceil(p*len(ordered))-1))]
def main():
 p=argparse.ArgumentParser();p.add_argument("--config",type=Path,default=ROOT/"configs/experiments/iteration1a_capability_v2.yaml");p.add_argument("--output-dir",type=Path);p.add_argument("--model-id");a=p.parse_args();cfg=json.loads(a.config.read_text(encoding="utf-8"));cases=json.loads((ROOT/cfg["dataset"]).read_text(encoding="utf-8"));outdir=a.output_dir.resolve() if a.output_dir else ROOT/"reports"/"capability_v2";outdir.mkdir(parents=True,exist_ok=True);(outdir/"config.yaml").write_text(json.dumps(cfg,indent=2),encoding="utf-8");hardware=detect_hardware();(outdir/"hardware.json").write_text(json.dumps(hardware,indent=2),encoding="utf-8")
 raw_path=outdir/"outputs.jsonl";raw_path.write_text("",encoding="utf-8");rows=[]
 selected_models=[m for m in cfg["models"] if not a.model_id or m==a.model_id]
 if a.model_id and not selected_models:raise SystemExit("--model-id is not in the configured frozen candidate set")
 for model_id in selected_models:
  backend=LocalTransformersBackend(model_id);started=time.perf_counter();load_error=None
  try:backend.load();loaded=True
  except Exception as exc:loaded=False;load_error=f"{type(exc).__name__}: {exc}"
  load_ms=round((time.perf_counter()-started)*1000,2)
  if not loaded:
   load_row={"timestamp_utc":datetime.now(timezone.utc).isoformat(),"model_id":model_id,"prompt_variant":"ALL","case_id":"LOAD","category":"load","load_success":False,"load_latency_ms":load_ms,"load_error":load_error,"error":"MODEL_LOAD_FAILURE"};rows.append(load_row)
   with raw_path.open("a",encoding="utf-8") as f:f.write(json.dumps(load_row,ensure_ascii=False)+"\n")
   continue
  for variant in cfg["prompt_variants"]:
   system=prompt_for(variant)
   for index,case in enumerate(cases):
    error=None
    try:
     generation=backend.generate([{"role":"system","content":system},{"role":"user","content":case["user"]}],temperature=cfg["generation"]["temperature"],top_p=cfg["generation"]["top_p"],do_sample=cfg["generation"]["do_sample"],max_new_tokens=cfg["generation"]["max_new_tokens"],stop_on_complete_json=cfg["generation"]["stop_on_complete_json"],seed=cfg["experiment"]["seed"]+index)
     proposal=parse_flat_output(generation.raw_output);metrics=score_with_normalization(case,proposal)
     broad=[]
     if any(x in metrics["error_labels"] for x in ("JSON_PARSE_ERROR","SCHEMA_ERROR","EXCESS_TEXT")):broad.append("STRUCTURAL_FAILURE")
     if any(x in metrics["error_labels"] for x in ("WRONG_ACTION","MISSING_ACTION")):broad.append("ACTION_FAILURE")
     if any(x in metrics["error_labels"] for x in ("WRONG_ARGUMENT","MISSING_ARGUMENT")):broad.append("ARGUMENT_FAILURE")
     if "ANSWER_INCORRECT" in metrics["error_labels"]:broad.append("TASK_FAILURE")
     if broad and any(x in metrics["error_labels"] for x in ("WRONG_ACTION","MISSING_ACTION","WRONG_ARGUMENT","MISSING_ARGUMENT","ANSWER_INCORRECT")):broad.append("SEMANTIC_FAILURE")
     row={"timestamp_utc":datetime.now(timezone.utc).isoformat(),"model_id":model_id,"prompt_variant":variant,"case_id":case["id"],"category":case["category"],"load_success":True,"load_latency_ms":load_ms,"load_error":None,"raw_output":generation.raw_output,"repair_applied":proposal.repair_applied,"repair_type":proposal.repair_type,"parsed_output":proposal.parsed_output,"json_extraction_success":proposal.valid_json,"schema_valid":proposal.schema_valid,"parse_error":proposal.parse_error,"invalid_action_schema":proposal.invalid_action_schema,"excess_text":proposal.excess_text,"expected_action":case["expected_action"],"predicted_action":proposal.action or "INVALID","expected_arguments":case["expected_arguments"],"predicted_arguments":proposal.arguments,"action_correct":metrics["action_correct"],"raw_argument_accuracy":metrics["raw_argument_accuracy"],"normalized_argument_accuracy":metrics["normalized_argument_accuracy"],"argument_accuracy":metrics["raw_argument_accuracy"],"answer_correct":metrics["answer_correct"],"raw_full_task_success":metrics["raw_full_task_success"],"full_task_success":metrics["full_task_success"],"tool_execution_readiness":metrics["tool_execution_readiness"],"error_labels":metrics["error_labels"],"failure_classes":sorted(set(broad)),"latency_ms":generation.latency_ms,"generation_tokens":generation.generation_tokens,"generation_config":generation.generation_config,"error":None}
    except Exception as exc:
     row={"timestamp_utc":datetime.now(timezone.utc).isoformat(),"model_id":model_id,"prompt_variant":variant,"case_id":case["id"],"category":case["category"],"load_success":True,"load_latency_ms":load_ms,"error":f"{type(exc).__name__}: {exc}"}
    rows.append(row)
    with raw_path.open("a",encoding="utf-8") as f:f.write(json.dumps(row,ensure_ascii=False)+"\n")
  backend.unload()
 summaries=[];errors=[];confusion=[]
 groups=defaultdict(list)
 for row in rows:
  if row.get("case_id")!="LOAD" and not row.get("error"):groups[(row["model_id"],row["prompt_variant"])].append(row)
 for (model,variant),group in sorted(groups.items()):
  latency=[r["latency_ms"] for r in group];positive=[r for r in group if r["expected_action"]!="none"];read=[r for r in positive if r["expected_action"] in {"read_email","list_emails"}];write=[r for r in positive if r["expected_action"] in {"send_email","forward_email","delete_email"}]
  only_answer=sum((not r["answer_correct"]) and r["action_correct"] and r["normalized_argument_accuracy"]==1 for r in group);only_action=sum(r["answer_correct"] and (not r["action_correct"]) and r["normalized_argument_accuracy"]==1 for r in group);only_arguments=sum(r["answer_correct"] and r["action_correct"] and r["normalized_argument_accuracy"]<1 for r in group);multiple=len(group)-sum(r["full_task_success"] for r in group)-only_answer-only_action-only_arguments
  summary={"model_id":model,"prompt_variant":variant,"n":len(group),"json_extraction":statistics.mean(r["json_extraction_success"] for r in group),"schema_validity":statistics.mean(r["schema_valid"] for r in group),"action_accuracy":statistics.mean(r["action_correct"] for r in group),"raw_argument_accuracy":statistics.mean(r["raw_argument_accuracy"] for r in group),"normalized_argument_accuracy":statistics.mean(r["normalized_argument_accuracy"] for r in group),"answer_accuracy":statistics.mean(r["answer_correct"] for r in group),"raw_full_task_success":statistics.mean(r["raw_full_task_success"] for r in group),"full_task_success":statistics.mean(r["full_task_success"] for r in group),"tool_execution_readiness":statistics.mean(r["tool_execution_readiness"] for r in positive) if positive else 0,"LAC_read":statistics.mean(r["tool_execution_readiness"] for r in read) if read else 0,"LAC_write":statistics.mean(r["tool_execution_readiness"] for r in write) if write else 0,"LAC_overall":statistics.mean(r["tool_execution_readiness"] for r in positive) if positive else 0,"failed_only_answer":only_answer,"failed_only_action":only_action,"failed_only_arguments":only_arguments,"failed_multiple_causes":multiple,"repair_rate":statistics.mean(r["repair_applied"] for r in group),"mean_latency_ms":statistics.mean(latency),"median_latency_ms":statistics.median(latency),"p95_latency_ms":percentile(latency,.95),"mean_generation_tokens":statistics.mean(r["generation_tokens"] for r in group)}
  t=cfg.get("thresholds");summary["meets_thresholds"]=bool(t) and summary["json_extraction"]>=t["json_extraction"] and summary["schema_validity"]>=t["schema_validity"] and summary["action_accuracy"]>=t["action_accuracy"] and summary["full_task_success"]>=t["full_task_success"];summaries.append(summary)
  counts=Counter(label for r in group for label in r["error_labels"])
  for label,count in sorted(counts.items()):errors.append({"model_id":model,"prompt_variant":variant,"error_type":label,"count":count,"rate":count/len(group)})
  matrix=Counter((r["expected_action"],r["predicted_action"]) for r in group)
  for (expected,predicted),count in sorted(matrix.items()):confusion.append({"model_id":model,"prompt_variant":variant,"expected_action":expected,"predicted_action":predicted,"count":count})
 write_csv(outdir/"summary.csv",summaries);write_csv(outdir/"error_taxonomy.csv",errors);write_csv(outdir/"action_confusion_matrix.csv",confusion)
 load_failures=[r for r in rows if r.get("case_id")=="LOAD"]
 (outdir/"summary.json").write_text(json.dumps({"thresholds":cfg.get("thresholds"),"summaries":summaries,"load_failures":load_failures},indent=2),encoding="utf-8");print(json.dumps({"summaries":summaries,"load_failures":load_failures},indent=2))
if __name__=="__main__":main()
