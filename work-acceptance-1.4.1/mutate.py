"""Mutation battery for the checker, counted against a baseline.

Every mutant of wa_der / wa_crypto / wa_tsa / wa_check is run against the
vectors. The UNMODIFIED checker is run first and the set P of vectors it
agrees with is recorded: a mutant counts as KILLED only if it disagrees
on a vector in P. A vector the unmodified checker already fails can never
"kill" anything, so a checker that fails vectors cannot score kills by
failing more of them (stillmarcus24/assurance-run#1).

    python -I mutate.py VECTORS_DIR [--jobs N] [--out FILE.json] [--limit N]

A mutant that does not finish in --timeout seconds is KILLED_BY_TIMEOUT and
reported on its own line, not hidden in the kill count.
"""
import argparse
import ast
import concurrent.futures
import copy
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MODULES = ("wa_der", "wa_crypto", "wa_tsa", "wa_check")
SUPPORT = ("run_vectors.py",)

_SWAP_CMP = {ast.Eq: ast.NotEq, ast.NotEq: ast.Eq, ast.Lt: ast.LtE, ast.LtE: ast.Lt,
             ast.Gt: ast.GtE, ast.GtE: ast.Gt, ast.In: ast.NotIn, ast.NotIn: ast.In,
             ast.Is: ast.IsNot, ast.IsNot: ast.Is}
_SWAP_BIN = {ast.Add: ast.Sub, ast.Sub: ast.Add, ast.BitXor: ast.BitAnd, ast.BitAnd: ast.BitOr,
             ast.BitOr: ast.BitAnd, ast.LShift: ast.RShift, ast.RShift: ast.LShift,
             ast.FloorDiv: ast.Mult, ast.Mod: ast.FloorDiv}


class Sites(ast.NodeVisitor):
    """Enumerates mutation sites in a stable order: (kind, node) pairs."""

    def __init__(self):
        self.sites = []

    def visit_Compare(self, node):
        for i, op in enumerate(node.ops):
            if type(op) in _SWAP_CMP:
                self.sites.append(("cmp", node, i))
        self.generic_visit(node)

    def visit_BoolOp(self, node):
        self.sites.append(("boolop", node, 0))
        self.generic_visit(node)

    def visit_UnaryOp(self, node):
        if isinstance(node.op, ast.Not):
            self.sites.append(("not", node, 0))
        self.generic_visit(node)

    def visit_BinOp(self, node):
        if type(node.op) in _SWAP_BIN:
            self.sites.append(("binop", node, 0))
        self.generic_visit(node)

    def visit_Constant(self, node):
        if isinstance(node.value, bool):
            self.sites.append(("bool", node, 0))
        elif isinstance(node.value, int) and not isinstance(node.value, bool):
            self.sites.append(("int", node, 0))
        elif isinstance(node.value, str) and node.value and len(node.value) < 40:
            self.sites.append(("str", node, 0))

    def visit_If(self, node):
        self.sites.append(("if", node, 0))
        self.generic_visit(node)

    def visit_Expr(self, node):
        if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute) \
                and node.value.func.attr in ("add", "append"):
            self.sites.append(("drop", node, 0))
        self.generic_visit(node)

    def visit_Return(self, node):
        if node.value is not None and not isinstance(node.value, ast.Constant):
            self.sites.append(("return_none", node, 0))
        self.generic_visit(node)

    def visit_Continue(self, node):
        self.sites.append(("continue", node, 0))

    def visit_Break(self, node):
        self.sites.append(("break", node, 0))


def _is_docstring(tree, node):
    for parent in ast.walk(tree):
        if isinstance(parent, (ast.Module, ast.FunctionDef, ast.ClassDef)) and parent.body:
            first = parent.body[0]
            if isinstance(first, ast.Expr) and first.value is node:
                return True
    return False


def enumerate_mutants(module):
    path = os.path.join(HERE, module + ".py")
    with open(path, encoding="utf-8") as fh:
        source = fh.read()
    tree = ast.parse(source)
    visitor = Sites()
    visitor.visit(tree)
    out = []
    for n, (kind, node, extra) in enumerate(visitor.sites):
        if kind == "str" and _is_docstring(tree, node):
            continue
        out.append((module, n, kind, node.lineno))
    return source, out


def apply_mutant(source, module, index):
    tree = ast.parse(source)
    visitor = Sites()
    visitor.visit(tree)
    kind, node, extra = visitor.sites[index]
    if kind == "cmp":
        node.ops[extra] = _SWAP_CMP[type(node.ops[extra])]()
    elif kind == "boolop":
        node.op = ast.Or() if isinstance(node.op, ast.And) else ast.And()
    elif kind == "not":
        _replace(tree, node, node.operand)
    elif kind == "binop":
        node.op = _SWAP_BIN[type(node.op)]()
    elif kind == "bool":
        node.value = not node.value
    elif kind == "int":
        node.value = node.value + 1
    elif kind == "str":
        node.value = node.value + "~"
    elif kind == "if":
        node.test = ast.UnaryOp(op=ast.Not(), operand=node.test)
    elif kind in ("drop", "continue", "break"):
        _replace(tree, node, ast.Pass())
    elif kind == "return_none":
        node.value = ast.Constant(value=None)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


def _replace(tree, old, new):
    for parent in ast.walk(tree):
        for field, value in ast.iter_fields(parent):
            if value is old:
                setattr(parent, field, new)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if item is old:
                        value[i] = new


def worker(workdir, vectors_dir, stop_on):
    """Run the vectors in order; with `stop_on` (the baseline-passing set) stop
    at the first of them that disagrees, since that already decides the mutant."""
    sys.path.insert(0, workdir)
    import run_vectors
    out, stopped = {}, None
    for f in run_vectors.load([vectors_dir]):
        (name, (ok, _, _)), = run_vectors.run([f]).items()
        out[name] = ok
        if not ok and name in stop_on:
            stopped = name
            break
    print(json.dumps({"results": out, "stopped_at": stopped}))


def classify(run, passing):
    """('killed'|'survived'|'timeout', vectors it was killed on). A mutant is
    killed only on a vector in `passing`, the set the UNMODIFIED checker
    agrees with; disagreeing on any other vector counts for nothing."""
    if run == "timeout":
        return "timeout", []
    if not run:
        return "killed", sorted(passing)  # does not even run
    if run.get("stopped_at"):
        return "killed", [run["stopped_at"]]
    result = run["results"]
    killed_on = sorted(v for v in passing if not result.get(v, False))
    return ("killed" if killed_on else "survived"), killed_on


def run_variant(sources, vectors_dir, timeout, stop_on=()):
    """sources: {module: text}. Returns {"results": {vector: bool}, "stopped_at": name|None},
    or "timeout"; {} when the mutant does not even run."""
    workdir = tempfile.mkdtemp(prefix="wa-mut-")
    try:
        for m in MODULES:
            text = sources.get(m)
            if text is None:
                shutil.copy(os.path.join(HERE, m + ".py"), workdir)
            else:
                with open(os.path.join(workdir, m + ".py"), "w", encoding="utf-8") as fh:
                    fh.write(text)
        for s in SUPPORT:
            shutil.copy(os.path.join(HERE, s), workdir)
        shutil.copy(os.path.abspath(__file__), workdir)
        try:
            proc = subprocess.run(
                [sys.executable, "-I", os.path.join(workdir, "mutate.py"), "--worker", workdir, vectors_dir,
                 json.dumps(sorted(stop_on))],
                capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return "timeout"
        if proc.returncode != 0:
            return {}  # a mutant that does not even run is killed on every vector
        try:
            return json.loads(proc.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return {}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def main(argv):
    if len(argv) > 1 and argv[1] == "--worker":
        worker(argv[2], argv[3], set(json.loads(argv[4])))
        return 0
    ap = argparse.ArgumentParser()
    ap.add_argument("vectors")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 2)
    ap.add_argument("--timeout", type=float, default=120)
    ap.add_argument("--out", default="mutation-result.json")
    ap.add_argument("--limit", type=int, default=0, help="only the first N mutants (smoke test)")
    args = ap.parse_args(argv[1:])

    base = run_variant({}, args.vectors, args.timeout * 2)
    if not isinstance(base, dict) or not base:
        print("baseline did not run", file=sys.stderr)
        return 2
    base = base["results"]
    passing = sorted(v for v, ok in base.items() if ok)
    failing = sorted(v for v, ok in base.items() if not ok)
    print(f"baseline: {len(passing)} of {len(base)} vectors agree; only those can kill a mutant")

    mutants, sources = [], {}
    for m in MODULES:
        src, found = enumerate_mutants(m)
        sources[m] = src
        mutants += found
    if args.limit:
        mutants = mutants[:args.limit]
    print(f"{len(mutants)} mutants over {', '.join(MODULES)}")

    def one(item):
        module, index, kind, line = item
        try:
            text = apply_mutant(sources[module], module, index)
            compile(text, module, "exec")
        except Exception:
            return item, "invalid", []
        status, killed_on = classify(run_variant({module: text}, args.vectors, args.timeout, passing), passing)
        return item, status, killed_on

    rows = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for n, (item, status, killed_on) in enumerate(pool.map(one, mutants), 1):
            rows.append(dict(module=item[0], site=item[1], kind=item[2], line=item[3],
                             status=status, killed_on=killed_on))
            if n % 50 == 0:
                print(f"  {n}/{len(mutants)}", flush=True)

    count = lambda s: sum(1 for r in rows if r["status"] == s)
    valid = len(rows) - count("invalid")
    summary = dict(
        baseline_agree=len(passing), baseline_disagree=failing, mutants=len(rows), invalid=count("invalid"),
        killed=count("killed"), killed_by_timeout=count("timeout"), survived=count("survived"),
        kill_rate_of_valid=round((count("killed") + count("timeout")) / valid, 4) if valid else None,
        timeout_counted_as_kill=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(dict(summary=summary, mutants=rows), fh, indent=1, sort_keys=True)
    print(json.dumps(summary, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
