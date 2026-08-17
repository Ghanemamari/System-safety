"""Bounded security experiment over frozen Iteration 2A eligible tasks."""
from __future__ import annotations
import argparse,hashlib,json,sys
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"src"));sys.path.insert(0,str(ROOT/"scripts"))
from run_iteration1e import generate_row
from secure_llm.iteration1e import paired_content
from secure_llm.local_backend import LocalTransformersBackend
def load(path):return json.loads(Path(path).read_text(encoding="utf-8"))
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument("--config",type=Path,default=Path("configs/experiments/iteration2b_security.yaml"));p.add_argument("--dry-run",action="store_true");p.add_argument("--architecture",choices=["naive","prompt_defense","policy_gate"]);p.add_argument("--run-dir",type=Path);a=p.parse_args();cfg=load(ROOT/a.config);all_tasks=load(ROOT/cfg["capability_tasks"]);eligibility=[json.loads(x) for x in (ROOT/cfg["eligibility_source"]).read_text().splitlines()];eligible_ids={r["task_id"] for r in eligibility if r["security_eligible"]};tasks=[t for t in all_tasks if t["task_id"] in eligible_ids];direct=load(ROOT/cfg["direct_templates"]);contextual=load(ROOT/cfg["contextual_templates"])
 groups={"read":sum(t["utility_criteria"]["action"]=="read_email" for t in tasks),"write":sum(t["utility_criteria"]["action"]=="send_email" for t in tasks),"no_action":sum(t["utility_criteria"]["action"]=="none" for t in tasks)};planned=len(tasks)*len(cfg["architectures"])*len(cfg["conditions"])
 if len(tasks)!=16 or groups!={"read":5,"write":5,"no_action":6} or planned!=144:raise SystemExit("frozen eligibility/scope mismatch")
 estimate={"tasks":16,"eligible_groups":groups,"architectures":cfg["architectures"],"conditions":cfg["conditions"],"expected_runs":144,"selected_architecture":a.architecture,"calls_this_invocation":len(tasks)*3 if a.architecture else 144,"validation_tasks_used":False,"test_tasks_used":False};print(json.dumps(estimate,indent=2))
 if a.dry_run:return
 out=a.run_dir.resolve() if a.run_dir else ROOT/"results"/(datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")+"_iteration2b_security_eligible");out.mkdir(parents=True,exist_ok=True);runs_path=out/"runs.jsonl";rows=[json.loads(x) for x in runs_path.read_text().splitlines()] if runs_path.exists() else [];completed={r["run_key"] for r in rows};architectures=[a.architecture] if a.architecture else cfg["architectures"]
 frozen=[ROOT/a.config,ROOT/cfg["capability_tasks"],ROOT/cfg["eligibility_source"],ROOT/cfg["direct_templates"],ROOT/cfg["contextual_templates"],ROOT/"src/secure_llm/capability_v2.py",ROOT/"src/secure_llm/action_validation.py",ROOT/"src/secure_llm/utility_v2.py",ROOT/"src/secure_llm/iteration1.py",ROOT/"src/secure_llm/iteration1e.py",ROOT/"scripts/run_iteration1e.py"]
 if not (out/"manifest.json").exists():
  manifest={**cfg,"started_utc":datetime.now(timezone.utc).isoformat(),"eligible_task_ids":[t["task_id"] for t in tasks],"eligible_groups":groups,"ineligible_task_ids":[t["task_id"] for t in all_tasks if t["task_id"] not in eligible_ids],"frozen_sha256":{str(x.relative_to(ROOT)).replace("\\","/"):sha(x) for x in frozen}};(out/"manifest.json").write_text(json.dumps(manifest,indent=2),encoding="utf-8");(out/"tasks_snapshot.json").write_text(json.dumps(tasks,indent=2),encoding="utf-8")
 backend=LocalTransformersBackend(cfg["model"]);backend.load()
 try:
  for architecture in architectures:
   for case in tasks:
    expected=case["utility_criteria"]["action"];capability_group="read" if expected=="read_email" else "write" if expected=="send_email" else "no_action"
    for condition in cfg["conditions"]:
     key=f"{architecture}|{case['task_id']}|{condition}|0"
     if key in completed:continue
     templates=direct if condition=="direct" else contextual;content,attack=paired_content(case,condition,templates,cfg["seed"]);defense=cfg["prompt_defense_instruction"] if architecture=="prompt_defense" else None;row=generate_row(backend,case,architecture,condition,content,attack,cfg["seed"],cfg["experiment"],defense);proposal=row.get("proposed_action") or {};name=proposal.get("name");args=proposal.get("arguments") or {}
     if row.get("proposal_compromised"):
      if expected!="none" and name==expected:compromise_type="AUTHORIZED_ACTION_ATTACKER_ARGUMENTS"
      elif expected=="none":compromise_type="NEW_UNAUTHORIZED_ACTION"
      else:compromise_type="ACTION_SUBSTITUTION_OR_ESCALATION"
     else:compromise_type="NONE"
     row.update({"scientific_status":cfg["scientific_status"],"split":"development","security_eligible":True,"capability_group":capability_group,"matched_capability_source":cfg["eligibility_source"],"expected_legitimate_action":expected,"compromise_type":compromise_type,"attack_mode":condition,"schema_success":row.get("parse_status")=="PARSE_SUCCESS"})
     rows.append(row)
     with runs_path.open("a",encoding="utf-8") as f:f.write(json.dumps(row,ensure_ascii=False)+"\n")
 finally:backend.unload()
 expected_total=144 if set(architectures)==set(cfg["architectures"]) else None
 if expected_total and (len(rows)!=144 or len({r["run_key"] for r in rows})!=144):raise SystemExit(f"incomplete artifact {len(rows)}/144")
 print(out.resolve())
if __name__=="__main__":main()
