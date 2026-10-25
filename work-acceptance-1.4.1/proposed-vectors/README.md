# Proposed vectors for work-acceptance-record 1.4.1

Four vectors for behaviour the 57 published vectors (`bc5a138`) do not pin, found by the
mutation battery in this directory's parent (see `../RESULT.md`). CC0, in the corpus
layout of `maximusrufus/work-acceptance-record/vectors/`.

| file | case | expected |
|---|---|---|
| `a1-receipt-exponent-numbers.json` | signed body holds 1.5e-7, 1.25e+22, 1.234e-10, 9.87654321e-8, 2.5e+21: RFC 8785 exponent form with more than one significant digit | no problems |
| `a2-receipt-key-outside-bmp.json` | signed body has keys `z`, U+1F600, U+FF61: RFC 8785 sorts by UTF-16 code unit, so U+1F600 comes before U+FF61 | no problems |
| `a3-envelope-key-id-differs-from-signed.json` | signed with key A, signed `key_id` names A, envelope `signature.key_id` names B (also in the key file) | `SIGNATURE_INVALID` |
| `a4-same-key-under-two-ids.json` | as 05, but the producer names a second id that holds the same public key as the checker's | as 05: `KEY_COLLISION`, `SELF_CHECKED` |

Each file carries the seeds of its test keys (`test_key_seeds`), so anyone can re-sign it.
Canonical bytes for signing were produced by Node's own `JSON.stringify` number formatting
and default (UTF-16) key sort, not by the checker under test.

## Readings left as questions, not vectors

The text does not settle these, so a vector would assert a reading rather than test one:

1. Fractional seconds in `issued_utc`, `committed_at` or a token `genTime`: compared at full precision, or truncated?
2. A base64 field (`signature.value`, `public_key_base64`) holding a character outside the alphabet: `SIGNATURE_INVALID`, `KEY_REJECTED`, or refused?
3. Upper-case hexadecimal in `criteria.sha256` or `files.*.sha256`: equal to the lower-case digest, or a mismatch?
4. A record token whose imprint matches but whose signed receipt has no `issued_utc`: `receipt_timestamp` `imprint_match` with which reference time?

## What the four add

The same 1,421-mutant battery, run on the 57 published vectors plus these four
(`mutation-result-61.json`, counted only on vectors the unmodified checker agrees with):
1,128 killed, 293 survive (was 1,115 and 306). All 13 newly killed mutants are in the
verification steps (`wa_check.py`): a1 kills 4, a2 1, a3 3, a4 5. Survivors in the
steps module go from 48 to 35.

    python3 -I run_vectors.py proposed-vectors            # 4/4 agree
    python3 -I mutate.py <57 vectors + these 4> --jobs 2   # 1,128 of 1,421 killed
