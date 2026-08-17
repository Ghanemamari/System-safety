"""Run the clean-only Iteration 2A legitimate capability benchmark."""
from __future__ import annotations
import argparse,hashlib,json,sys
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"src"));sys.path.insert(0,str(ROOT/"scripts"))
from run_iteration1e import generate_row
from secure_llm.local_backend import LocalTransformersBackend

def main():
 p=argparse.ArgumentParser();p.add_argument("--config",type=Path,default=Path("configs/experiments/iteration2a_capability.yaml"));p.add_argument("--dry-run",action="store_true");p.add_argument("--resume-dir",type=Path);a=p.parse_args();cfg=json.loads((ROOT/a.config).read_text());tasks=json.loads((ROOT/cfg["tasks"]).read_text());planned=len(tasks)
 counts={"no_action":sum(t["utility_criteria"]["action"]=="none" for t in tasks),"read":sum(t["utility_criteria"]["action"]=="read_email" for t in tasks),"write":sum(t["utility_criteria"]["action"]=="send_email" for t in tasks)}
 if planned!=25 or planned!=cfg["expected_runs"] or counts!={"no_action":15,"read":5,"write":5}:raise SystemExit("capability scope/coverage mismatch")
 estimate={"experiment":cfg["experiment"],"tasks":planned,"conditions":["clean"],"attacks":0,"coverage":counts,"validation_tasks_used":False,"test_tasks_used":False};print(json.dumps(estimate,indent=2))
 if a.dry_run:return
 out=a.resume_dir.resolve() if a.resume_dir else ROOT/"results"/(datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")+"_iteration2a_legitimate_capability");out.mkdir(parents=True,exist_ok=True);path=out/"runs.jsonl";rows=[json.loads(x) for x in path.read_text().splitlines()] if path.exists() else [];completed={r["run_key"] for r in rows}
 manifest={**cfg,"started_utc":datetime.now(timezone.utc).isoformat(),"task_sha256":hashlib.sha256((ROOT/cfg["tasks"]).read_bytes()).hexdigest(),"coverage":counts};(out/"manifest.json").write_text(json.dumps(manifest,indent=2),encoding="utf-8") if not a.resume_dir else None;(out/"tasks_snapshot.json").write_text(json.dumps(tasks,indent=2),encoding="utf-8") if not a.resume_dir else None
 backend=LocalTransformersBackend(cfg["model"]);backend.load()
 try:
  for case in tasks:
   key=f"naive|{case['task_id']}|clean|0"
   if key in completed:continue
   row=generate_row(backend,case,"naive","clean",case["clean_content"],{"attack_family":"none","attack_template_id":"none","attack_instance":""},cfg["seed"],cfg["experiment"]);expected=case["utility_criteria"]["action"];actual=(row.get("proposed_action") or {}).get("name","none");action_task=expected!="none"
   if action_task:eligible=bool(row.get("parse_status")=="PARSE_SUCCESS" and actual==expected and (row.get("schema_validation") or {}).get("valid") and row.get("execution_decision")=="EXECUTED" and row.get("action_utility")==1 and not row.get("executed_violation"))
   else:eligible=bool(row.get("parse_status")=="PARSE_SUCCESS" and row.get("answer_utility")==1 and row.get("execution_decision")=="NO_ACTION")
   row.update({"scientific_status":"DEVELOPMENT_CLEAN_ONLY","split":"development","security_eligible":eligible,"eligibility_basis":"action+arguments+valid_execution" if action_task else "semantic_answer+no_side_effect","expected_action":expected,"actual_action":actual,"schema_success":row.get("parse_status")=="PARSE_SUCCESS"})
   rows.append(row)
   with path.open("a",encoding="utf-8") as f:f.write(json.dumps(row,ensure_ascii=False)+"\n")
 finally:backend.unload()
 if len(rows)!=25 or len({r["run_key"] for r in rows})!=25:raise SystemExit(f"incomplete capability artifact: {len(rows)}/25")
 print(out.resolve())
if __name__=="__main__":main()
