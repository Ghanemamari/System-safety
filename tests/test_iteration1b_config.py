from __future__ import annotations
import json,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class Iteration1BConfigTests(unittest.TestCase):
 def test_frozen_protocol(self):
  old=json.loads((ROOT/"configs/experiments/iteration1a_capability_v2.yaml").read_text());new=json.loads((ROOT/"configs/experiments/iteration1b_model_selection.yaml").read_text());self.assertEqual(old["dataset"],new["dataset"]);self.assertEqual(old["generation"],new["generation"]);self.assertEqual(old["thresholds"],new["thresholds"]);self.assertEqual(["P2"],new["prompt_variants"]);self.assertFalse(new["security_benchmark_enabled"])
 def test_exact_candidates(self):
  new=json.loads((ROOT/"configs/experiments/iteration1b_model_selection.yaml").read_text());self.assertEqual(["Qwen/Qwen2-1.5B-Instruct","HuggingFaceTB/SmolLM2-1.7B-Instruct","google/gemma-3-1b-it"],new["models"])
if __name__=="__main__":unittest.main()
