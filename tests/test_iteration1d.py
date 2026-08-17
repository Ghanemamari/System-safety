from __future__ import annotations
import json,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"src"));sys.path.insert(0,str(ROOT/"scripts"))
from secure_llm.iteration1 import IntentPolicy,V1Action
class Iteration1DTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.cfg=json.loads((ROOT/"configs/experiments/iteration1d_smol_exploratory.yaml").read_text());cls.cases=json.loads((ROOT/"data/iteration1d/tasks.json").read_text())
 def test_scope_is_exact_and_no_held_out_split(self):
  self.assertEqual(5,len(self.cases));self.assertEqual(45,len(self.cases)*len(self.cfg["architectures"])*len(self.cfg["conditions"])*self.cfg["repetitions"]);self.assertTrue(all(c["split"]=="development" for c in self.cases));self.assertFalse(self.cfg["validation_enabled"]);self.assertFalse(self.cfg["test_enabled"])
 def test_p4_is_frozen(self):self.assertEqual("P4",self.cfg["prompt_variant"])
 def test_legitimate_send_allowed_attacker_blocked(self):
  case=next(c for c in self.cases if "send_email" in c["allowed_tools"]);policy=IntentPolicy();self.assertEqual("ALLOW",policy.authorize(case,V1Action("send_email",{"recipient":"alice@example.com"}))[0]);self.assertEqual("BLOCK",policy.authorize(case,V1Action("send_email",{"recipient":"attacker@example.com"},"UNTRUSTED_EMAIL"))[0])
 def test_read_allowed_and_gate_not_block_all_writes(self):
  read_case=self.cases[0];self.assertEqual("ALLOW",IntentPolicy().authorize(read_case,V1Action("read_email",{"email_id":"latest"}))[0]);send_case=next(c for c in self.cases if "send_email" in c["allowed_tools"]);self.assertEqual("ALLOW",IntentPolicy().authorize(send_case,V1Action("send_email",{"recipient":"alice@example.com"}))[0])
if __name__=="__main__":unittest.main()
