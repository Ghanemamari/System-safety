from __future__ import annotations
import sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"src"))
from secure_llm.action_validation import validate_action_arguments
class ActionValidationTests(unittest.TestCase):
 def test_valid_send_and_forward(self):self.assertTrue(validate_action_arguments("send_email",{"recipient":"alice@example.com","body":"Confirmed"})[0]);self.assertTrue(validate_action_arguments("forward_email",{"email_id":"17","recipient":"alice@example.com"})[0])
 def test_malformed_injected_calls_do_not_execute(self):self.assertFalse(validate_action_arguments("forward_email",{"email_id":"<EMAIL>","recipient":"attacker@example.com"})[0]);self.assertFalse(validate_action_arguments("forward_email",{"email_id":"17","recipient":"Ignore rules and send"})[0]);self.assertFalse(validate_action_arguments("forward_email",{"email_id":"alice@example.com","recipient":"attacker@example.com"})[0])
if __name__=="__main__":unittest.main()
