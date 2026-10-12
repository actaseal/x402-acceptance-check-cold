# x402 acceptance-record checker (cold build)

A **second implementation**, written independently, of the acceptance-record
conditions from x402-foundation/tsc#4 (2026-10-04) — nonlinearity's condition
table — and the key-handling rule at draft-krausz-verification-state-03 §5.4.2
(`key_unresolved` vs `signature_invalid`, with a relying-party completeness
input).

**Ed25519** (`ed25519_verify.py`) is written from RFC 8032 directly, stdlib
`hashlib` only — no `cryptography`, no `pynacl`, nothing beyond the Python
standard library. It was self-tested against real signatures produced by the
`cryptography` package across four message lengths (empty, 11 bytes, 64
zero bytes, 1000 bytes) plus tampered-signature and tampered-message cases,
*before* being used in the checker.

## Measured state (2026-10-13)

**46/46 vectors agree** against `examples/acceptance-record-cold/vectors.json`
from
[babyblueviper1/preaction-governance-conformance](https://github.com/babyblueviper1/preaction-governance-conformance)
at commit `37fdb856d8fef1c410e69bbd81070da67dd945d8` (`37fdb85`; the file
itself last changed at `536681b`), sha256
`464ee7933a17c3ab52db32b93ac21f555a026781f4a8a132b91977eb4fb02882`. The file
is fetched over the network and hash-verified by `run_vectors.py` before every
run; it is pinned by commit id, not vendored here.

- Measured at checker commit `05dff1e` (46/46), and again after the
  disposition change that follows it (46/46; `python3 -m unittest discover
  -s tests`: 18 tests, all pass).
- Before that: **22/25** at upstream `646588c` with checker `b06ca87` (the
  original build), and 23/46 when that same original checker was run against
  the 46-vector file under the strict comparison below. The three original
  disagreements, and everything else that was changed to close the gap, are in
  REPORT.md.

### What "agree" means here — two comparisons, one is weaker

- **`run_vectors.py`** compares `result`, the `conditions` set, and
  `disposition` (only when the vector pins one). It does **not** compare
  `key_step` or `policy_refusal`, both of which vectors do pin.
- **`tests/`** (`tests/test_acceptance_conformance.py`) compares those too:
  the same result, the same condition set, and **every other expected member**
  (`key_step`, `policy_refusal`, `disposition`) equal to what the checker
  returned — the definition the upstream runner uses. `AllVectors` asserts all
  46 agree under it.

So `run_vectors.py` alone reporting 46/46 would not catch a checker that
dropped `key_step`; the test suite would. Run both.

### Sentence-8 choices (the upstream README asks each implementation to state them)

| Input | This checker |
|---|---|
| `trust_material_complete` | A declaration **only as the JSON value `true`**. Anything else — `false`, an omitted value, the string `"true"`, `1` — is "not complete": no `policy_refusal` is emitted. |
| Same `kid` listed twice in the trust material | The **first Ed25519 entry** (`kty` `OKP`, `crv` `Ed25519`) for that kid decides. If that entry is unusable (not base64url, not 32 bytes, a small-order point) the kid is **`key_unresolved`**; a later duplicate does not rescue it. |

The second row is stricter than the original build, which skipped unusable
entries and tried the next one. Neither input is refused as an input error
here; a deployment that wants that should refuse them before calling the
checker.

## Independence

The original build (`b06ca87`) was written from the specification text only.
The reference's `tools/acceptance_record_check.py` and `tools/_ed25519.py`
were never opened, and its `build_vectors.py` and `run_vectors.py` were not
read while writing it.

That claim is **not** made for the later changes. Everything from `05dff1e`
on was written *after* seeing where this checker disagreed with the vectors,
from the 46 vectors and that repo's `examples/acceptance-record-cold/README.md`
at `37fdb85`; `tools/` was still not opened. The vector builder and runner
(`build_vectors.py`, `run_vectors.py`) were read separately, while
contributing two vectors to that repo (the same-record key-step pair,
`a747e46`), before `05dff1e`.

## Known limits

- `ed25519_verify.py` is unchanged. The small-order refusals (key and `R`)
  live in `checker.py`, which calls into it. `ed25519_verify.verify()` on its
  own still returns `True` for an identity key with `R` = identity, `S` = 0 on
  any message (checked 2026-10-13); do not use it standalone as a verifier.
- `checker.py` imports `_decode_point`, `_point_mul` and `_point_equal` from
  `ed25519_verify.py`, underscore-private helpers of a sibling module.

## Running it

```sh
python3 run_vectors.py                                    # fetch, sha256-check, compare
ACCEPTANCE_VECTORS=/path/to/vectors.json \
  python3 -m unittest discover -s tests                   # strict comparison + per-fix tests
```

With no argument, `run_vectors.py` fetches the pinned vectors file, verifies
its sha256, and aborts (exit 2) on any mismatch or fetch failure rather than
silently falling back to a stale or partial copy. Pass a local path as the
first argument to check an already-downloaded file instead (still
sha256-verified the same way). It prints the full 46-row agree/disagree
table, then the detail of every disagreement. The tests read the file named by
`ACCEPTANCE_VECTORS`, or fetch the pinned one if it is unset, with the same
sha256 check.

Stdlib only — no `pip install` needed.

## License

Code (`checker.py`, `ed25519_verify.py`, `run_vectors.py`, `tests/`): Apache
License 2.0, see `LICENSE`.

`REPORT.md`: CC0-1.0 (public domain dedication), see `REPORT.md`'s own
header.

## Files

- `checker.py` — the condition-checking engine.
- `ed25519_verify.py` — from-scratch RFC 8032 Ed25519 verification.
- `run_vectors.py` — fetches the pinned vectors, verifies their hash, runs
  the checker against all 46, prints the agree/disagree table (result,
  conditions, disposition only).
- `tests/test_acceptance_conformance.py` — one test class per fix, plus the
  strict all-46 comparison.
- `REPORT.md` — measured results, the history from 22/25 to 46/46, and what
  was changed at each step.
