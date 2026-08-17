from __future__ import annotations
import argparse,json,statistics,sys
from collections import defaultdict
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"src"))
from secure_llm.capability_v2 import parse_flat_output,score_with_normalization
def main():
 p=argparse.ArgumentParser();p.add_argument("--outputs",type=Path,required=True);p.add_argument("--dataset",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args();cases={x["id"]:x for x in json.loads(a.dataset.read_text(encoding="utf-8"))};rows=[json.loads(x) for x in a.outputs.read_text(encoding="utf-8").splitlines()];groups=defaultdict(list)
 for row in rows:
  if row.get("case_id") not in cases or row.get("error"):continue
  metrics=score_with_normalization(cases[row["case_id"]],parse_flat_output(row["raw_output"]));row.update(metrics);groups[(row["model_id"],row["prompt_variant"])].append(row)
 summaries=[]
 for (model,variant),group in sorted(groups.items()):
  positive=[r for r in group if r["expected_action"]!="none"];read=[r for r in positive if r["expected_action"] in {"read_email","list_emails"}];write=[r for r in positive if r["expected_action"] in {"send_email","forward_email","delete_email"}]
  summaries.append({"model_id":model,"prompt_variant":variant,"n":len(group),"json_extraction":statistics.mean(r["valid_json"] if "valid_json" in r else r["json_extraction_success"] for r in group),"schema_validity":statistics.mean(parse_flat_output(r["raw_output"]).schema_valid for r in group),"action_accuracy":statistics.mean(r["action_correct"] for r in group),"raw_argument_accuracy":statistics.mean(r["raw_argument_accuracy"] for r in group),"normalized_argument_accuracy":statistics.mean(r["normalized_argument_accuracy"] for r in group),"answer_accuracy":statistics.mean(r["answer_correct"] for r in group),"full_task_success":statistics.mean(r["full_task_success"] for r in group),"tool_execution_readiness":statistics.mean(r["tool_execution_readiness"] for r in positive),"LAC_read":statistics.mean(r["tool_execution_readiness"] for r in read),"LAC_write":statistics.mean(r["tool_execution_readiness"] for r in write),"LAC_overall":statistics.mean(r["tool_execution_readiness"] for r in positive)})
 result={"summaries":summaries};a.output.write_text(json.dumps(result,indent=2),encoding="utf-8");print(json.dumps(result,indent=2))
if __name__=="__main__":main()
