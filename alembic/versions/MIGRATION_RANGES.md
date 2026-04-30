# Migration Sequence Reservation — Phase 3

To prevent parallel branches from creating conflicting migration numbers,
each Phase 3 issue has a reserved range:

| Range     | Issue  | Feature               |
|-----------|--------|-----------------------|
| 0003–0009 | US #7  | Session management    |
| 0010–0019 | US #8  | Email verification    |
| 0020–0029 | US #9  | Subscriptions         |
| 0030–0039 | US #10 | 2FA / TOTP            |
| 0040      | US #63 | Merge multi-heads     |

Name your migration files with the appropriate prefix, e.g.:
`0010_add_verification_tokens.py` for US #8.
