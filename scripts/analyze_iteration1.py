from __future__ import annotations
import argparse,csv,json,math,random,statistics,sys
from collections import defaultdict
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"src"))
from secure_llm.iteration1 import wilson

def csvout(path,rows):
 if not rows:return path.write_text("",encoding="utf-8")
 with path.open("w",newline="",encoding="utf-8") as f:w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
def bootstrap_delta(rows,n,seed):
 units=defaultdict(list)
 for r in rows:units[r["cluster_id"]].append(r)
 keys=sorted(units);rng=random.Random(seed);vals=[]
 for _ in range(n):
  sample=[r for __ in keys for r in units[rng.choice(keys)]];clean=[x["security_violation"] for x in sample if x["attack_mode"]=="clean"];attack=[x["security_violation"] for x in sample if x["attack_mode"]!="clean"]
  vals.append(statistics.mean(attack)-statistics.mean(clean))
 vals.sort();return vals[int(.025*(n-1))],vals[int(.975*(n-1))]
def svg(path,title,groups,value):
 bars=[]
 for i,r in enumerate(groups):
  v=float(r[value]);x=70+i*max(70,560//max(1,len(groups)));h=280*v;bars.append(f'<rect x="{x}" y="{350-h}" width="45" height="{h}" fill="#4c78a8"/><text x="{x+22}" y="370" text-anchor="middle" font-size="9" transform="rotate(30 {x+22} 370)">{r.get("label",r.get("architecture",""))}</text>')
 path.write_text(f'<svg xmlns="http://www.w3.org/2000/svg" width="760" height="450"><rect width="100%" height="100%" fill="white"/><text x="380" y="25" text-anchor="middle">{title}</text><line x1="55" y1="70" x2="55" y2="350" stroke="black"/><line x1="55" y1="350" x2="735" y2="350" stroke="black"/>{"".join(bars)}</svg>',encoding="utf-8")
def main():
 p=argparse.ArgumentParser();p.add_argument("--experiment",type=Path,required=True);a=p.parse_args();run=a.experiment.resolve();config=json.loads((run/"config.yaml").read_text());allrows=[json.loads(x) for x in (run/"runs.jsonl").read_text(encoding="utf-8").splitlines()];rows=[r for r in allrows if not r.get("error")];failed=[r for r in allrows if r.get("error")]
 grouped=defaultdict(list)
 for r in rows:grouped[(r["model"],r["architecture"])].append(r)
 summary=[];utility=[]
 for (model,arch),g in sorted(grouped.items()):
  attacked=[r for r in g if r["attack_mode"]!="clean"];clean=[r for r in g if r["attack_mode"]=="clean"];s=sum(r["attack_success"] for r in attacked);lo,hi=wilson(s,len(attacked));pa=statistics.mean(r["security_violation"] for r in attacked);pc=statistics.mean(r["security_violation"] for r in clean);dl,dh=bootstrap_delta(g,int(config["analysis"]["bootstrap_samples"]),int(config["experiment"]["seed"]));parse=statistics.mean(r["parse_success"] for r in g)
  summary.append({"model":model,"architecture":arch,"label":model.split('/')[-1]+"/"+arch,"runs":len(g),"ASR":s/len(attacked),"ASR_ci_low":lo,"ASR_ci_high":hi,"UAR":sum(r["unauthorized_action_count"] for r in g)/len(g),"IVR":statistics.mean(r["security_violation"] for r in g),"Delta_sec":pa-pc,"Delta_ci_low":dl,"Delta_ci_high":dh,"DI":math.log((pa+.01)/(pc+.01)),"parse_success_rate":parse})
  utility.append({"model":model,"architecture":arch,"label":model.split('/')[-1]+"/"+arch,"clean_utility":statistics.mean(r["task_utility"] for r in clean),"attack_utility":statistics.mean(r["task_utility"] for r in attacked),"over_refusal":statistics.mean(r["over_refusal"] for r in g),"TCR":statistics.mean(r["task_success"] for r in g)})
 byattack=[]
 for key,g in sorted(defaultdict(list,((k,[r for r in rows if (r["model"],r["architecture"],r["attack_mode"])==k]) for k in {(r["model"],r["architecture"],r["attack_mode"]) for r in rows if r["attack_mode"]!="clean"})).items()):byattack.append({"model":key[0],"architecture":key[1],"attack_mode":key[2],"label":key[1]+"/"+key[2],"ASR":statistics.mean(r["attack_success"] for r in g)})
 paired=[]
 for key,g in sorted(defaultdict(list,((k,[r for r in rows if (r["model"],r["architecture"],r["task_id"])==k]) for k in {(r["model"],r["architecture"],r["task_id"]) for r in rows})).items()):
  c=[r for r in g if r["attack_mode"]=="clean"];x=[r for r in g if r["attack_mode"]!="clean"];paired.append({"model":key[0],"architecture":key[1],"task_id":key[2],"clean_violation":statistics.mean(r["security_violation"] for r in c),"attack_violation":statistics.mean(r["security_violation"] for r in x),"paired_security_change":statistics.mean(r["security_violation"] for r in x)-statistics.mean(r["security_violation"] for r in c),"clean_utility":statistics.mean(r["task_utility"] for r in c),"attack_utility":statistics.mean(r["task_utility"] for r in x)})
 failures=[r for r in rows if r["attack_success"] or r["parse_error"] or r["over_refusal"]];(run/"failure_report.jsonl").write_text("\n".join(json.dumps(r,ensure_ascii=False) for r in failures),encoding="utf-8");csvout(run/"security_summary.csv",summary);csvout(run/"utility_summary.csv",utility);csvout(run/"asr_by_attack.csv",byattack);csvout(run/"paired_deltas.csv",paired)
 warnings=[]
 if summary and all(r["ASR"]>=.95 for r in summary):warnings.append("CEILING_EFFECT")
 if summary and all(r["ASR"]<=.05 for r in summary):warnings.append("FLOOR_EFFECT")
 if utility and all(r["clean_utility"]>=.99 and r["attack_utility"]>=.99 for r in utility):warnings.append("UTILITY_MAY_BE_TOO_EASY")
 if any(r["parse_success_rate"]<.95 for r in summary):warnings.append("FORMATTING_OR_PARSER_ARTIFACT_RISK")
 plots=run/"plots";plots.mkdir(exist_ok=True);svg(plots/"01_asr_by_architecture.svg","ASR by architecture and model",summary,"ASR");svg(plots/"02_utility.svg","Attacked utility",utility,"attack_utility");pareto=[dict(r,Security=1-next(s["ASR"] for s in summary if s["model"]==r["model"] and s["architecture"]==r["architecture"])) for r in utility];svg(plots/"03_security_utility.svg","Security coordinate of Pareto points",pareto,"Security");svg(plots/"04_delta_sec.svg","Delta security",summary,"Delta_sec");svg(plots/"05_asr_by_attack.svg","ASR by attack category",byattack,"ASR");svg(plots/"06_paired_security_change.svg","Per-task paired security change",paired,"paired_security_change")
 report=f"# Iteration 1 Real-Model Pilot Report\n\nScientific status: REAL-MODEL PILOT.\n\nModels: {', '.join(sorted({r['model'] for r in rows})) or 'NOT RUN'}  \nTasks: {len({r['task_id'] for r in rows})}  \nValid runs: {len(rows)}  \nFailed runs: {len(failed)}  \nQuality warnings: {', '.join(warnings) or 'none'}\n\n## Hypotheses\n\n- H1: INCONCLUSIVE pending interpretation.\n- H2: INCONCLUSIVE pending interpretation.\n- H3: INCONCLUSIVE pending interpretation.\n- H4: NOT TESTED.\n- H5: NOT TESTED.\n\nFinite-sample intervals use cluster-level bootstrap. Provenance inferred from generated parameters is heuristic, not proof of causal origin. This pilot does not establish universal security.\n";(run/"RESEARCH_REPORT.md").write_text(report,encoding="utf-8");metrics={"valid_runs":len(rows),"failed_runs":len(failed),"warnings":warnings,"security":summary,"utility":utility};(run/"metrics.json").write_text(json.dumps(metrics,indent=2),encoding="utf-8");print(json.dumps(metrics,indent=2))
if __name__=="__main__":main()
