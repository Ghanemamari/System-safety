from __future__ import annotations
import json,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
import sys;sys.path.insert(0,str(ROOT/"src"))
from secure_llm.utility_v2 import evaluate_task
class CapabilityBenchmarkTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.tasks=json.loads((ROOT/"data/iteration2a/capability_tasks.json").read_text());cls.cfg=json.loads((ROOT/"configs/experiments/iteration2a_capability.yaml").read_text())
 def test_clean_development_only_and_no_leakage(self):
  self.assertEqual(25,len(self.tasks));self.assertTrue(all(t["split"]=="development" for t in self.tasks));self.assertFalse(any("attack_goal" in t for t in self.tasks));self.assertFalse(self.cfg["attacks_enabled"]);self.assertFalse(self.cfg["validation_tasks_used"]);self.assertFalse(self.cfg["test_tasks_used"])
 def test_minimum_category_opportunities(self):
  actions=[t["utility_criteria"]["action"] for t in self.tasks];self.assertEqual(15,actions.count("none"));self.assertEqual(5,actions.count("read_email"));self.assertEqual(5,actions.count("send_email"))
 def test_required_task_types(self):
  clusters={t["task_cluster"] for t in self.tasks};self.assertTrue({"summarization","classification","information_extraction","read_action","write_action"}<=clusters)
 def test_action_tasks_have_explicit_arguments(self):
  for t in self.tasks:
   if t["utility_criteria"]["action"]!="none":self.assertTrue(t["utility_criteria"].get("required_arguments"))
 def test_classification_accepts_unique_declared_label_not_competitors(self):
  case=self.tasks[5];self.assertTrue(evaluate_task(case,"This is high priority.",None,True)["task_success"]);self.assertFalse(evaluate_task(case,"It may be medium or high.",None,True)["task_success"])
 def test_semantic_hyphen_equivalence_does_not_change_identifiers(self):
  case=self.tasks[4];self.assertTrue(evaluate_task(case,"Legal approved a twelve-month renewal beginning October 1.",None,True)["task_success"])
if __name__=="__main__":unittest.main()
