# x402 acceptance-record checker (cold build)

A **second, independent implementation** of the acceptance-record conditions
from x402-foundation/tsc#4 (2026-10-04) — nonlinearity's condition table —
and the key-handling rule at draft-krausz-verification-state-03 §5.4.2
(`key_unresolved` vs `signature_invalid`, with a relying-party
completeness input). Written from the specification text only.

**The reference implementation was never opened.** These four files in the
public source clone were not read at any point while writing this:
`tools/acceptance_record_check.py`, `tools/_ed25519.py`, `build_vectors.py`,
`run_vectors.py` (that repo's own runner). Only the vectors' input data and
this repo's own reading of the spec were used.

**Ed25519** (`ed25519_verify.py`) is written from RFC 8032 directly, stdlib
`hashlib` only — no `cryptography`, no `pynacl`, nothing beyond the Python
standard library. It was self-tested against real signatures produced by the
`cryptography` package across four message lengths (empty, 11 bytes, 64
zero bytes, 1000 bytes) plus tampered-signature and tampered-message cases,
*before* being used in the checker.

**Vectors**: `examples/acceptance-record-cold/vectors.json` from
[babyblueviper1/preaction-governance-conformance](https://github.com/babyblueviper1/preaction-governance-conformance)
at commit `646588cbab5e3cfe0824af6bb83ee1779f0f67ee` (25 vectors), sha256
`c7f5513a6292a8cb7a8049b30113ed9bb786843717c62e7f806c73843c04e7e0` — fetched
over the network and hash-verified by `run_vectors.py` before every run; see
below. The file is pinned by commit id, not vendored into this repo.

**Headline**: of the two implementations, **22/25 vectors agree exactly on
every field the published vector actually pins** (result, conditions, and
disposition where the vector specifies one). The remaining **3 reduce to
two confirmed reading differences** on fields both implementations pin
(whether a failed signature is its own result token, and what counts as a
well-typed sha256 digest member) — plus a third, broader question the
vectors are silent on rather than contradicting (whether a non-clean result
should ever report a `disposition` at all). **No expectation, reading, or
behavior in this checker was changed after seeing where it disagreed with
the vectors** — see REPORT.md for the full vector-by-vector table and the
specific source-text sentence each reading rests on, both readings stated
neutrally with no winner declared.

A note on that 22/25 figure, stated plainly rather than buried: an earlier
pass of this report's own comparison script counted 15 disagreements, by
treating a vector's silence on `disposition` (it has no `disposition` key
at all for `malformed`/`key_unresolved`-family results) as if it meant
"expected: null," which inflated apparent disagreement on 12 vectors where
`result` and `conditions` actually matched exactly. That was a bug in the
*comparison script*, found and fixed before this was published — not a
change to the checker's own logic or to any vector's expectation. The three
real, substantive differences stand unchanged.

## Running it

```sh
python3 run_vectors.py
```

With no argument, this fetches the pinned vectors file over the network,
verifies its sha256, and aborts (exit 2) on any mismatch or fetch failure
rather than silently falling back to a stale or partial copy. Pass a local
path as the first argument to check an already-downloaded file instead
(still sha256-verified the same way). Prints the full 25-row agree/disagree
table, then the detail of every disagreement.

Stdlib only — no `pip install` needed.

## License

Code (`checker.py`, `ed25519_verify.py`, `run_vectors.py`): Apache License
2.0, see `LICENSE`.

`REPORT.md`: CC0-1.0 (public domain dedication), see `REPORT.md`'s own
header.

## Files

- `checker.py` — the condition-checking engine.
- `ed25519_verify.py` — from-scratch RFC 8032 Ed25519 verification.
- `run_vectors.py` — fetches the pinned vectors, verifies their hash, runs
  the checker against all 25, prints the agree/disagree table.
- `REPORT.md` — full vector-by-vector results and the three reading
  differences, each tied to the specific sentence of the source text it
  rests on.
