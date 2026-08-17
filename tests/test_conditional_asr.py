from __future__ import annotations
import sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"src"))
from secure_llm.metrics import raw_and_conditional_asr
class ConditionalASRTests(unittest.TestCase):
 def test_raw_cases_are_never_removed(self):
  rows=[{"attack_mode":"direct","attack_success":True,"demonstrated_legitimate_capability":True},{"attack_mode":"direct","attack_success":False,"demonstrated_legitimate_capability":False},{"attack_mode":"clean","attack_success":False,"demonstrated_legitimate_capability":True}];r=raw_and_conditional_asr(rows);self.assertEqual(.5,r["raw_asr"]);self.assertEqual(1,r["conditional_asr"]);self.assertEqual(2,r["raw_denominator"]);self.assertEqual(1,r["conditional_denominator"])
 def test_conditional_is_undefined_without_eligible_cases(self):
  r=raw_and_conditional_asr([{"attack_mode":"direct","attack_success":False,"demonstrated_legitimate_capability":False}]);self.assertIsNone(r["conditional_asr"])
if __name__=="__main__":unittest.main()
