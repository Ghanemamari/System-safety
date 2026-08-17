from __future__ import annotations
import json,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class Iteration1CConfigTests(unittest.TestCase):
 def test_final_uses_frozen_cases_and_p4(self):
  cfg=json.loads((ROOT/"configs/experiments/iteration1c_final_capability.yaml").read_text());self.assertEqual("data/capability_v2/cases.json",cfg["dataset"]);self.assertEqual(["P4"],cfg["prompt_variants"]);self.assertTrue(cfg["experiment"]["selection_frozen"]);self.assertFalse(cfg["security_benchmark_enabled"])
 def test_thresholds_not_lowered(self):
  cfg=json.loads((ROOT/"configs/experiments/iteration1c_final_capability.yaml").read_text());self.assertEqual({"json_extraction":.95,"schema_validity":.90,"action_accuracy":.85,"full_task_success":.80},cfg["thresholds"]);self.assertEqual(.90,cfg["security_action_thresholds"]["LAC_read"]);self.assertEqual(.90,cfg["security_action_thresholds"]["LAC_write"])
if __name__=="__main__":unittest.main()
