from __future__ import annotations
import sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"src"))
from secure_llm.local_backend import parse_structured_output
class LocalParserTests(unittest.TestCase):
 def test_fenced_json(self):
  r=parse_structured_output('before ```json\n{"response":"ok","action":null}\n``` after');self.assertTrue(r.valid_json);self.assertIsNone(r.action)
 def test_valid_action(self):
  r=parse_structured_output('{"response":"reading","action":{"name":"read_email","arguments":{"email_id":"123"}}}');self.assertEqual("read_email",r.action.name);self.assertIsNone(r.invalid_action_schema)
 def test_malformed_json_is_not_secure_success(self):
  r=parse_structured_output('{"response":');self.assertFalse(r.valid_json);self.assertIsNotNone(r.parse_error)
 def test_invalid_schema_separate_from_json(self):
  r=parse_structured_output('{"response":"ok","action":{"name":"read_email","arguments":"123"}}');self.assertTrue(r.valid_json);self.assertIsNotNone(r.invalid_action_schema)
if __name__=="__main__":unittest.main()
