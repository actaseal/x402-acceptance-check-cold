"""Run the checker against the work-acceptance-record vectors and print
AGREE or DIFF per vector. Standard library only.

    python -I run_vectors.py DIR_OR_FILES...      # DIR holds the vectors/*.json
    python -I run_vectors.py --fetch              # download the 57 vectors at the pinned commit first

An absent `tsa_signature` reads as `not_evaluated`, per the README. A vector
that lists `tsa_signature_accepted` accepts any of those values for that token.
"""
import glob
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # -I drops it

import wa_check  # noqa: E402

PINNED = "bc5a1385a9347701ff4557126d73b50b3575fe93"
RAW = "https://raw.githubusercontent.com/maximusrufus/work-acceptance-record/%s/vectors/%s"
API = "https://api.github.com/repos/maximusrufus/work-acceptance-record/git/trees/%s?recursive=1"


def fetch(dest):
    os.makedirs(dest, exist_ok=True)
    with urllib.request.urlopen(API % PINNED, timeout=30) as resp:
        tree = json.load(resp)["tree"]
    names = sorted(t["path"].split("/", 1)[1] for t in tree if t["path"].startswith("vectors/"))
    for name in names:
        with urllib.request.urlopen(RAW % (PINNED, name), timeout=30) as resp:
            data = resp.read()
        with open(os.path.join(dest, name), "wb") as fh:
            fh.write(data)
    return names


def _norm(outcome):
    out = dict(outcome)
    if "tsa_signature" in out:
        out["tsa_signature"] = dict(out["tsa_signature"])
    return out


def agree(vector, got):
    exp = _norm(vector["expected"])
    got = _norm(got)
    accepted = vector.get("tsa_signature_accepted") or {}
    for side in ("criteria", "receipt"):
        g = (got.get("tsa_signature") or {}).get(side)
        e = (exp.get("tsa_signature") or {}).get(side)
        if g is None and e is None:
            continue
        if (g or "not_evaluated") == (e or "not_evaluated") or g in accepted.get(side, ()):
            continue
        return False
    exp.pop("tsa_signature", None)
    got.pop("tsa_signature", None)
    for lst in ("problem_codes", "warning_codes"):
        if lst in exp:
            exp[lst] = sorted(exp[lst])
    return exp == got


def load(paths):
    files = []
    for p in paths:
        files += sorted(glob.glob(os.path.join(p, "*.json"))) if os.path.isdir(p) else [p]
    return files


def run(files, check=wa_check.check):
    results = {}
    for f in files:
        with open(f, encoding="utf-8") as fh:
            vector = json.load(fh)
        try:
            got = check(vector["inputs"])
            ok = agree(vector, got)
        except Exception as exc:  # a crash is a disagreement, never a pass
            got, ok = {"crash": repr(exc)}, False
        results[os.path.basename(f)] = (ok, got, vector["expected"])
    return results


def main(argv):
    args = argv[1:]
    if args and args[0] == "--fetch":
        dest = args[1] if len(args) > 1 else "vectors"
        fetch(dest)
        args = [dest]
    files = load(args)
    if not files:
        print("no vectors given", file=sys.stderr)
        return 2
    results = run(files)
    for name, (ok, got, exp) in results.items():
        print(("AGREE " if ok else "DIFF  ") + name)
        if not ok:
            print("   expected", json.dumps(exp, sort_keys=True))
            print("   got     ", json.dumps(got, sort_keys=True))
    n = sum(1 for ok, _, _ in results.values() if ok)
    print(f"{n}/{len(results)} agree")
    return 0 if n == len(results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
