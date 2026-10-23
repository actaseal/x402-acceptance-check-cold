# Work-acceptance record checker, clean room, profile 1.4.1

A second, independent reading of `maximusrufus/work-acceptance-record`
(draft profile 1.4.1, schema `trilatic.acceptance-receipt/1.2`), written
from that repository's `README.md` and `vectors/` at commit
`bc5a1385a9347701ff4557126d73b50b3575fe93` only. The reference verifier and
every other checker were not opened. Python standard library only, no
network, no clock: every certificate date is compared with the token's
own genTime.

| file | what it does |
|---|---|
| `wa_check.py` | steps 1-8 and the outcome object; RFC 8785 with ECMAScript numbers |
| `wa_tsa.py` | RFC 3161 TSTInfo reading (imprint, genTime, accuracy) and step 9 `tsa_signature` |
| `wa_crypto.py` | Ed25519 with the prime-order key rule, ECDSA P-256/P-384, RSA PKCS#1 v1.5 and PSS (verification only) |
| `wa_der.py` | strict DER reader |
| `run_vectors.py` | `AGREE` / `DIFF` per vector; `--fetch DIR` downloads the 57 vectors at the pinned commit |
| `mutate.py` | mutation battery, kills counted against a baseline (below) |
| `tests/` | unit tests, the 57-vector test, the baseline-counting tests |
| `RESULT.md` | measured numbers and the readings the vectors do not pin |

```
python -I run_vectors.py --fetch vectors          # 57/57 agree
python -I wa_check.py vectors/01-valid.json        # the outcome object
python -I mutate.py vectors --jobs 8               # the battery
python -I tests/test_checker.py                    # WA_VECTORS=vectors to skip the download
```

`-I` removes the script directory from the import path; every entry point
puts it back itself.

## The mutation battery

`mutate.py` applies one change at a time to the four modules (comparison
swaps, `and`/`or`, dropped `not`, boolean and integer constants, string
constants, negated `if`, dropped `set.add` / `append`, `return` to `None`,
`continue`/`break` removed). **The unmodified checker is run first, and a
mutant counts as killed only on a vector the unmodified checker agrees
with.** A checker that already fails vectors cannot raise its kill count by
failing more of them. A mutant that runs past the timeout is reported on
its own line (`killed_by_timeout`), and one that does not even run is a
kill on every baseline vector.
