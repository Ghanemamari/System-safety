from __future__ import annotations
import json,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"src"))
from secure_llm.action_validation import validate_action_arguments
from secure_llm.utility_v2 import evaluate_task

class Iteration1ETests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.tasks=json.loads((ROOT/"data/iteration1e/tasks.json").read_text())
 def test_five_diverse_development_tasks(self):
  self.assertEqual(5,len(self.tasks));self.assertTrue(all(t["split"]=="development" for t in self.tasks));self.assertTrue(any(t["utility_criteria"]["action"]=="none" for t in self.tasks));self.assertTrue(any(t["utility_criteria"]["action"]=="read_email" for t in self.tasks));self.assertTrue(any(t["utility_criteria"]["action"]=="send_email" for t in self.tasks))
 def test_semantic_receipt_alternative(self):
  case=self.tasks[3];score=evaluate_task(case,"We received the proposal and will review it by Thursday.",None,True);self.assertEqual(1.0,score["answer_utility"]);self.assertTrue(score["task_success"])
 def test_no_action_side_effect_fails_system_utility(self):
  case=self.tasks[2];score=evaluate_task(case,"high",{"name":"send_email","arguments":{"recipient":"x@y.com","body":"x"}},True);self.assertEqual(1.0,score["answer_utility"]);self.assertEqual(0.0,score["system_task_utility"])
 def test_send_body_terminal_punctuation_is_normalized(self):
  case=self.tasks[4];executed={"name":"send_email","arguments":{"recipient":"alice@example.com","subject":"Meeting confirmed","body":"Our Tuesday meeting at 10:00 is confirmed"}};self.assertTrue(evaluate_task(case,"I will send it.",executed,True)["task_success"])
 def test_parser_failure_is_separate(self):
  score=evaluate_task(self.tasks[0],"correct prose",None,False);self.assertEqual(["PARSER_FAILURE"],score["failure_labels"]);self.assertIsNone(score["answer_utility"])

class EveryToolSchemaTests(unittest.TestCase):
 def test_read_email(self):self.assertTrue(validate_action_arguments("read_email",{"email_id":"RD-1"})[0]);self.assertFalse(validate_action_arguments("read_email",{})[0])
 def test_list_emails(self):self.assertTrue(validate_action_arguments("list_emails",{})[0]);self.assertTrue(validate_action_arguments("list_emails",{"folder":"inbox"})[0]);self.assertFalse(validate_action_arguments("list_emails",{"folder":3})[0])
 def test_send_email(self):self.assertTrue(validate_action_arguments("send_email",{"recipient":"a@example.com","subject":"s","body":"b"})[0]);self.assertFalse(validate_action_arguments("send_email",{"recipient":"a@example.com"})[0])
 def test_forward_email(self):self.assertTrue(validate_action_arguments("forward_email",{"email_id":"M-1","recipient":"a@example.com"})[0]);self.assertFalse(validate_action_arguments("forward_email",{"email_id":"M-1","recipient":"bad"})[0])
 def test_delete_email(self):self.assertTrue(validate_action_arguments("delete_email",{"email_id":"M-1"})[0]);self.assertFalse(validate_action_arguments("delete_email",{"email_id":"<id>"})[0])
 def test_unknown_and_extra_arguments(self):self.assertFalse(validate_action_arguments("shell",{})[0]);self.assertFalse(validate_action_arguments("delete_email",{"email_id":"M-1","force":True})[0])
if __name__=="__main__":unittest.main()
