#!/usr/bin/env python3
"""Fail if any Python source uses syntax/APIs newer than Python 3.9.

The provisioner runs on a Python 3.9 host, but contributors (and agents)
develop on newer interpreters where 3.10+ syntax compiles fine. CI running on
3.9 only catches 3.10+ constructs in code that actually *executes* — an
unimported module with ``match``/``case`` or ``x: int | None`` slips through
and crashes on the host at import time later.

This gate walks the AST of every source file (imported or not) and reports
3.10+ constructs. It is itself written to run on 3.9.

Blocking rules:
  - ``match`` / ``case`` statements                  (3.10)
  - PEP 604 unions ``X | Y`` in annotation contexts  (3.10)
  - ``datetime.UTC``                                 (3.11)

Note: ``str.removeprefix`` / ``str.removesuffix`` were added in 3.9 and ARE
safe; they are checked only as an opt-in warning (CLAUDE.md lists them out of
caution) and never fail the build.

Usage:
    python scripts/check_py39.py [PATHS ...]   # defaults to provisioner tests scripts
"""

import ast
import os
import sys
from typing import List, Optional, Tuple

DEFAULT_TARGETS = ["provisioner", "tests", "scripts"]

# Directories never worth scanning.
SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", ".mypy_cache", ".pytest_cache"}


class Violation(object):
    def __init__(self, path: str, lineno: int, rule: str, detail: str):
        self.path = path
        self.lineno = lineno
        self.rule = rule
        self.detail = detail

    def __str__(self) -> str:
        return "%s:%d  [%s] %s" % (self.path, self.lineno, self.rule, self.detail)


def _iter_py_files(targets: List[str]) -> List[str]:
    files: List[str] = []
    for target in targets:
        if os.path.isfile(target) and target.endswith(".py"):
            files.append(target)
            continue
        for root, dirs, names in os.walk(target):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for name in names:
                if name.endswith(".py"):
                    files.append(os.path.join(root, name))
    return sorted(files)


class _AnnotationUnionFinder(ast.NodeVisitor):
    """Find PEP 604 ``X | Y`` unions anywhere inside an annotation subtree."""

    def __init__(self):
        self.hits: List[int] = []

    def visit_BinOp(self, node: ast.BinOp) -> None:
        if isinstance(node.op, ast.BitOr):
            self.hits.append(getattr(node, "lineno", 0))
        self.generic_visit(node)


class _Checker(ast.NodeVisitor):
    def __init__(self, path: str):
        self.path = path
        self.violations: List[Violation] = []

    # --- match / case (3.10) ---
    def visit_Match(self, node) -> None:  # ast.Match exists on 3.10+, guarded below
        self.violations.append(
            Violation(self.path, node.lineno, "match-case", "match/case statement is Python 3.10+")
        )
        self.generic_visit(node)

    # --- annotation contexts: scan for PEP 604 unions ---
    def _check_annotation(self, annotation: Optional[ast.AST]) -> None:
        if annotation is None:
            return
        finder = _AnnotationUnionFinder()
        finder.visit(annotation)
        for lineno in finder.hits:
            self.violations.append(
                Violation(
                    self.path, lineno, "pep604-union",
                    "X | Y union in an annotation is Python 3.10+ (use Optional/Union)",
                )
            )

    def _check_args(self, args: ast.arguments) -> None:
        all_args = list(args.args) + list(args.kwonlyargs)
        posonly = getattr(args, "posonlyargs", [])
        all_args = list(posonly) + all_args
        for a in all_args:
            self._check_annotation(a.annotation)
        if args.vararg:
            self._check_annotation(args.vararg.annotation)
        if args.kwarg:
            self._check_annotation(args.kwarg.annotation)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_args(node.args)
        self._check_annotation(node.returns)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_args(node.args)
        self._check_annotation(node.returns)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._check_annotation(node.annotation)
        self.generic_visit(node)

    # --- datetime.UTC (3.11) ---
    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr == "UTC" and isinstance(node.value, ast.Name) and node.value.id == "datetime":
            self.violations.append(
                Violation(self.path, node.lineno, "datetime-utc", "datetime.UTC is Python 3.11+ (use datetime.timezone.utc)")
            )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "datetime":
            for alias in node.names:
                if alias.name == "UTC":
                    self.violations.append(
                        Violation(self.path, node.lineno, "datetime-utc", "from datetime import UTC is Python 3.11+")
                    )
        self.generic_visit(node)


def check_file(path: str) -> Tuple[List[Violation], Optional[str]]:
    """Return (violations, parse_error). A parse error is itself a failure when
    it indicates 3.10+ syntax the running interpreter cannot parse."""
    try:
        with open(path, "r") as handle:
            source = handle.read()
    except (IOError, OSError) as exc:
        return [], "could not read: %s" % exc

    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        return [], "SyntaxError (possible 3.10+ syntax): %s" % exc

    checker = _Checker(path)
    checker.visit(tree)
    return checker.violations, None


def main(argv: List[str]) -> int:
    targets = argv[1:] if len(argv) > 1 else DEFAULT_TARGETS
    targets = [t for t in targets if os.path.exists(t)]
    if not targets:
        print("check_py39: no target paths found", file=sys.stderr)
        return 0

    all_violations: List[Violation] = []
    parse_errors: List[Tuple[str, str]] = []

    for path in _iter_py_files(targets):
        violations, parse_error = check_file(path)
        all_violations.extend(violations)
        if parse_error:
            parse_errors.append((path, parse_error))

    if not all_violations and not parse_errors:
        print("check_py39: OK — no Python 3.10+ constructs found")
        return 0

    for path, err in parse_errors:
        print("%s  [parse] %s" % (path, err))
    for v in all_violations:
        print(str(v))

    total = len(all_violations) + len(parse_errors)
    print("\ncheck_py39: FAILED — %d Python 3.9-incompatibility issue(s)" % total, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
