# Measured result, profile 1.4.1 at bc5a138

- Vectors: 57/57 agree (`python -I run_vectors.py vectors`).
- Mutation battery: 1,421 mutants; baseline agrees on all 57, so every vector counts.
  1,115 killed, 306 survive (78.5% of valid mutants), 0 by timeout, 0 invalid.
  Full per-mutant list: `mutation-result.json`.

| module | mutants | survive |
|---|---|---|
| wa_check (steps 1-8, RFC 8785) | 365 | 48 |
| wa_tsa (RFC 3161, step 9) | 452 | 110 |
| wa_der (DER reader) | 202 | 81 |
| wa_crypto (Ed25519, ECDSA, RSA) | 402 | 67 |

## Readings in wa_check the 57 vectors do not pin

1. RFC 8785 numbers outside the plain-decimal range: exponent form (abs >= 1e21, abs < 1e-6) and negative numbers. Vector 57 covers integer-valued doubles only.
2. Object keys outside the BMP: RFC 8785 sorts by UTF-16 code unit; no vector has such a key.
3. Envelope `signature.key_id` differing from the signed `key_id`.
4. Producer and checker naming the same `key_id`, or one key listed under two ids.
5. Fractional seconds in timestamps.
6. Base64 outside the alphabet (strict decode).
7. Upper-case hex in a hash field.
8. `receipt_timestamp` = `imprint_match` with no issue time.

Survivors in the CLI entry point (lines 17, 280-288) are not checker behaviour.
