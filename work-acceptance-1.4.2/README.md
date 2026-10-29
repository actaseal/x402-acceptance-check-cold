# Work-acceptance record checker, profile 1.4.2

The 1.4.1 clean-room checker in `../work-acceptance-1.4.1/` (frozen, unchanged),
updated to profile 1.4.2 from the rule text only: step 10 and the changelog of
`maximusrufus/work-acceptance-record` `README.md` at commit
`cb7e8f1b888f1426e0daae6576f4dcfe86b1dad5`. The reference verifier and every
other checker were not opened. Python standard library only.

**Answer-exposed.** Before this update the frozen 1.4.1 checker was run on the
same 90 vectors (72/90, no crashes; `../work-acceptance-1.4.1/run-cb7e8f1-90-frozen.txt`),
so it was known which vectors each 1.4.2 rule touches. Vector descriptions
were read for 66, 68, 70, 76 and 88 (the time readings). One reading was fixed
after the first run: a party `key_id` of `null` is not a stated key (vector 01),
while an empty string is (vector 80).

| run | result |
|---|---|
| 01-90 at `cb7e8f1` | 90/90 (`run-cb7e8f1-90.txt`) |
| 6,750 single-field changes to the 90 inputs (wrong types, malformed times and base64) | no crash; one class (a wrongly typed `tsa_roots_base64`) crashed the first cut and is now refused |

```
python -I run_vectors.py --fetch vectors     # 90/90 agree
```

What changed from 1.4.1, by rule:

- canonical base64 for every value read; a non-canonical token or criteria file
  is the corresponding mismatch, never a refusal
- a `key_id` listed more than once is `KEY_REJECTED`; for the signing key no
  signature check runs, for a producer or checker key independence is `self-checked`
- genTime only as DER GeneralizedTime `YYYYMMDDHHMMSS[.fff]Z`, real calendar
  fields; any other form gives no usable time (warning, fall back to
  `committed_at`). The criteria time is rounded up to the millisecond, the
  reference time down; `committed_at` is compared with genTime to the second
- stated times RFC 3339 UTC; one that step 5 uses and cannot read is
  `RECEIPT_TIME_UNREADABLE`
- independence by key, keys compared as decoded bytes; a stated party `key_id`
  under an `independent` claim must be non-empty and listed once
- a record or input of the wrong type is refused
- a token with no usable genTime gives `tsa_signature` `failed` when anchors are
  supplied (no time to check the chain at); `not_evaluated` without anchors
