from __future__ import annotations
import re
from typing import Any

EMAIL_RE=re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
def _text(value:Any)->str:return str(value).strip() if value is not None else ""
def _id(value:Any)->bool:
 text=_text(value);return bool(text) and "<" not in text and ">" not in text and "@" not in text and " " not in text
def validate_action_arguments(action:str,arguments:dict[str,Any]) -> tuple[bool,str]:
 if not isinstance(arguments,dict):return False,"arguments_not_object"
 schemas={
  "read_email":({"email_id"},{"email_id"}),
  "list_emails":(set(),{"folder"}),
  "send_email":({"recipient","body"},{"recipient","subject","body"}),
  "forward_email":({"email_id","recipient"},{"email_id","recipient"}),
  "delete_email":({"email_id"},{"email_id"}),
 }
 if action not in schemas:return False,"unknown_action"
 required,allowed=schemas[action]
 keys=set(arguments)
 if missing:=required-keys:return False,"missing_required_arguments:"+",".join(sorted(missing))
 if extra:=keys-allowed:return False,"unexpected_arguments:"+",".join(sorted(extra))
 if action=="read_email":return (_id(arguments.get("email_id")),"valid" if _id(arguments.get("email_id")) else "invalid_email_id")
 if action=="list_emails":
  valid="folder" not in arguments or isinstance(arguments["folder"],str)
  return valid,"valid" if valid else "folder_must_be_string"
 if action=="send_email":
  valid=isinstance(arguments.get("recipient"),str) and bool(EMAIL_RE.fullmatch(_text(arguments.get("recipient")))) and isinstance(arguments.get("body"),str) and bool(_text(arguments.get("body"))) and ("subject" not in arguments or isinstance(arguments["subject"],str))
  return valid,"valid" if valid else "send_requires_valid_recipient_and_body"
 if action=="forward_email":
  valid=_id(arguments.get("email_id")) and bool(EMAIL_RE.fullmatch(_text(arguments.get("recipient"))))
  return valid,"valid" if valid else "forward_requires_valid_email_id_and_recipient"
 if action=="delete_email":return (_id(arguments.get("email_id")),"valid" if _id(arguments.get("email_id")) else "invalid_email_id")
 return False,"unknown_action"
