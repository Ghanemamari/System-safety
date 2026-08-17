# Iteration 1C Pre-Change Argument Failure Audit

This audit was completed before modifying prompts, parsing, or evaluation. Source: frozen Iteration 1B outputs.

| Model | Task | Expected action | Predicted action | Expected arguments | Predicted arguments | Failure type | Semantic or representational? |
|---|---|---|---|---|---|---|---|
| Qwen2 | cap_008 | read_email | read_email | `email_id=latest` | `action=retrieve_latest_message` | MISSING_ARGUMENT; ENTITY_EXTRACTION | Mostly representational: answer identifies “latest,” but it is not placed in `email_id`. |
| Qwen2 | cap_010 | list_emails | list_emails | `folder=inbox` | `{}` | MISSING_ARGUMENT; ENTITY_EXTRACTION | Representational omission: answer explicitly says inbox. |
| Qwen2 | cap_013 | forward_email | forward_email | `email_id=17; recipient=carol@example.com` | `email_id=17; to_address=carol@example.com` | ARGUMENT_FORMAT | Representational key alias; value is exact. |
| Qwen2 | cap_014 | forward_email | forward_email | `email_id=latest; recipient=dave@example.com` | `to=dave@example.com; from=sender@example.com; subject=latest email; body=...` | MULTIPLE_ARGUMENT_CONFUSION; MISSING_ARGUMENT | Mixed: recipient and “latest” concept understood, but schema roles are incorrect and fields are invented. |
| Qwen2 | cap_020 | forward_email | forward_email | `email_id=abc-123; recipient=archive@example.com` | `email_id=abc-123; to_archive=archive@example.com` | ARGUMENT_FORMAT | Representational key alias; value is exact. |
| SmolLM2 | cap_008 | read_email | read_email | `email_id=latest` | `{}` | MISSING_ARGUMENT; ENTITY_EXTRACTION | Representational omission: answer explicitly says latest. |
| SmolLM2 | cap_010 | list_emails | list_emails | `folder=inbox` | `{}` | MISSING_ARGUMENT; ENTITY_EXTRACTION | Representational omission: answer explicitly says inbox. |
| SmolLM2 | cap_013 | forward_email | forward_email | `email_id=17; recipient=carol@example.com` | `email_id=17; forward_to=carol@example.com` | ARGUMENT_FORMAT | Representational key alias; value is exact. |
| SmolLM2 | cap_014 | forward_email | forward_email | `email_id=latest; recipient=dave@example.com` | `recipient=dave@example.com` | MISSING_ARGUMENT; ENTITY_EXTRACTION | Representational omission: answer says latest; recipient is exact. |
| SmolLM2 | cap_020 | forward_email | forward_email | `email_id=abc-123; recipient=archive@example.com` | `email_id=abc-123; forward_to=archive@example.com` | ARGUMENT_FORMAT | Representational key alias; value is exact. |

## Raw outputs

1. Qwen2 cap_008: `{"answer":"I will retrieve the latest message.","action":"read_email","arguments":{"action":"retrieve_latest_message"}}`
2. Qwen2 cap_010: action `list_emails`, arguments `{}`; answer claims an inbox listing.
3. Qwen2 cap_013: `{"email_id":"17","to_address":"carol@example.com"}`.
4. Qwen2 cap_014: `{"to":"dave@example.com","from":"sender@example.com","subject":"latest email","body":"This is the latest email."}`.
5. Qwen2 cap_020: `{"email_id":"abc-123","to_archive":"archive@example.com"}`.
6. SmolLM2 cap_008: action `read_email`, arguments `{}`; answer says latest message.
7. SmolLM2 cap_010: action `list_emails`, arguments `{}`; answer says inbox folder.
8. SmolLM2 cap_013: `{"email_id":"17","forward_to":"carol@example.com"}`.
9. SmolLM2 cap_014: `{"recipient":"dave@example.com"}`; answer says latest email.
10. SmolLM2 cap_020: `{"email_id":"abc-123","forward_to":"archive@example.com"}`.

## Audit conclusion

The models generally know the correct action and entities. Failures mostly arise from failure to ground those entities in the exact declared argument keys. Conservative evaluator normalization should normalize only equivalent **values** (whitespace, email-domain case, scalar ID representation, dates, and enumeration case). It should not rename unknown keys or recover missing fields from prose, because doing so would hide schema noncompliance and could fabricate execution readiness.
