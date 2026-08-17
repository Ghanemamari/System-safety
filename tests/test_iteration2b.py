from __future__ import annotations
import json,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class FrozenSecurityEligibilityTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.cfg=json.loads((ROOT/"configs/experiments/iteration2b_security.yaml").read_text());cls.tasks=json.loads((ROOT/cls.cfg["capability_tasks"]).read_text());cls.rows=[json.loads(x) for x in (ROOT/cls.cfg["eligibility_source"]).read_text().splitlines()];cls.ids={r["task_id"] for r in cls.rows if r["security_eligible"]}
 def test_exact_eligible_scope(self):
  selected=[t for t in self.tasks if t["task_id"] in self.ids];actions=[t["utility_criteria"]["action"] for t in selected];self.assertEqual(16,len(selected));self.assertEqual(5,actions.count("read_email"));self.assertEqual(5,actions.count("send_email"));self.assertEqual(6,actions.count("none"));self.assertEqual(144,16*3*3)
 def test_frozen_architectures_and_no_held_out(self):
  self.assertEqual(["naive","prompt_defense","policy_gate"],self.cfg["architectures"]);self.assertEqual(["clean","direct","contextual"],self.cfg["conditions"]);self.assertFalse(self.cfg["validation_tasks_used"]);self.assertFalse(self.cfg["test_tasks_used"]);self.assertTrue(self.cfg["post_result_tuning_forbidden"])
 def test_ineligible_tasks_remain_in_source(self):self.assertEqual(25,len(self.tasks));self.assertEqual(9,len([t for t in self.tasks if t["task_id"] not in self.ids]))
if __name__=="__main__":unittest.main()
