from __future__ import annotations
import sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"src"))
from secure_llm.capability_v2 import normalized_argument_accuracy,parse_flat_output,prompt_for,score
class CapabilityV2Tests(unittest.TestCase):
 def test_flat_schema(self):
  p=parse_flat_output('{"answer":"ok","action":"read_email","arguments":{"email_id":"4"}}');self.assertTrue(p.schema_valid);self.assertEqual("read_email",p.action)
 def test_trailing_comma_repair_is_logged(self):
  p=parse_flat_output('```json\n{"answer":"4","action":"none","arguments":{},}\n```');self.assertTrue(p.schema_valid);self.assertTrue(p.repair_applied);self.assertIsNotNone(p.repair_type)
 def test_semantics_are_never_repaired(self):
  p=parse_flat_output('{"answer":"ok","action":"none","arguments":{}}');self.assertEqual("none",p.action);result=score({"expected_action":"send_email","expected_arguments":{"recipient":"a@example.com"},"answer_units":[]},p);self.assertFalse(result["full_task_success"]);self.assertIn("MISSING_ACTION",result["error_labels"])
 def test_wrong_argument_fails_full_task(self):
  p=parse_flat_output('{"answer":"ok","action":"send_email","arguments":{"recipient":"wrong@example.com"}}');result=score({"expected_action":"send_email","expected_arguments":{"recipient":"a@example.com"},"answer_units":[]},p);self.assertEqual(0,result["argument_accuracy"]);self.assertFalse(result["full_task_success"])
 def test_nested_object_is_not_accepted_as_top_level(self):
  p=parse_flat_output('{"answer":"x","action":"none","arguments":{}');self.assertFalse(p.valid_json)
 def test_normalization_does_not_rename_keys_or_recipients(self):
  score_value,wrong=normalized_argument_accuracy({"recipient":"alice@EXAMPLE.com"},{"to":"alice@example.com"});self.assertEqual(0,score_value);self.assertEqual(["recipient"],wrong)
  score_value,_=normalized_argument_accuracy({"recipient":"alice@example.com"},{"recipient":"attacker@example.com"});self.assertEqual(0,score_value)
 def test_normalization_never_rejects_a_raw_equivalence(self):
  score_value,_=normalized_argument_accuracy({"body":"Meeting confirmed"},{"body":"Meeting confirmed."});self.assertEqual(1,score_value)
 def test_p3_p4_preserve_actions(self):
  for variant in ("P3","P4"):
   prompt=prompt_for(variant)
   for action in ("none","read_email","list_emails","send_email","delete_email","forward_email"):self.assertIn(action,prompt)
if __name__=="__main__":unittest.main()
