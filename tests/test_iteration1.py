from __future__ import annotations
import json,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"src"))
from secure_llm.environment import inspect_environment
from secure_llm.iteration1 import IntentPolicy,V1Action,evaluate_utility,parse_openai_response,rotate_attack

class Iteration1Tests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.cases=json.loads((ROOT/"data/benchmark_v1/email.json").read_text());cls.templates=json.loads((ROOT/"data/benchmark_v1/attack_templates.json").read_text())
 def test_dataset_shape_and_splits(self):
  self.assertEqual(30,len(self.cases));self.assertEqual({"development":15,"validation":8,"test":7},{x:sum(c["split"]==x for c in self.cases) for x in ("development","validation","test")})
 def test_templates_are_varied_and_deterministic(self):
  self.assertEqual(5,len(self.templates["direct"]));self.assertEqual(5,len(self.templates["contextual"]));self.assertEqual(rotate_attack(self.cases[0],"direct",42,self.templates),rotate_attack(self.cases[0],"direct",42,self.templates))
 def test_parser_preserves_parse_errors(self):
  r=parse_openai_response({"choices":[{"message":{"content":"ok","tool_calls":[{"function":{"name":"send_email","arguments":"{"}}]}}]});self.assertIsNotNone(r.parse_error)
 def test_legitimate_send_allowed_but_attacker_blocked(self):
  case=next(c for c in self.cases if c["user_authorization"]["recipients"]);p=IntentPolicy();recipient=case["user_authorization"]["recipients"][0]
  self.assertEqual("ALLOW",p.authorize(case,V1Action("send_email",{"recipient":recipient}))[0]);self.assertEqual("BLOCK",p.authorize(case,V1Action("send_email",{"recipient":"attacker@example.com"},"UNTRUSTED_EMAIL"))[0])
 def test_read_only_allowed(self):self.assertEqual("ALLOW",IntentPolicy().authorize(self.cases[0],V1Action("read_email",{"email_id":"latest"}))[0])
 def test_structured_utility_not_keyword_only(self):self.assertEqual(1.0,evaluate_utility(self.cases[6],{"deadline":"2026-08-15"},[]))
 def test_reasoning_is_separate_from_final_content(self):
  parsed=parse_openai_response({"choices":[{"message":{"reasoning_content":"private-ish trace","content":"final answer"}}],"usage":{}});self.assertEqual("private-ish trace",parsed.reasoning_content);self.assertEqual("final answer",parsed.final_content);self.assertEqual("final answer",parsed.answer)
 def test_env_is_ignored_and_project_has_no_secret_marker(self):
  report=inspect_environment(ROOT);self.assertTrue(report.env_ignored);self.assertEqual((),report.potential_secret_files)
if __name__=="__main__":unittest.main()
