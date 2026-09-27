"""Architectural enforcement of ground-truth isolation (spec §3, docs/ground_truth.md §1).

Static checks parse every module with ``ast`` (imports resolved, including relative ones;
docstrings ignored), and a runtime check imports the package in a clean interpreter.
These tests guard every later phase, so they are strict by design.
"""

from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
PKG = SRC / "mlfref"

# package -> modules it must never import (prefix match on absolute module names)
FORBIDDEN_IMPORTS = {
    "reconstruction": (
        "mlfref.ground_truth",
        "mlfref.evaluation",
        "mlfref.experiment_id",  # human IDs encode the attack (D-014, D-021)
        "mlfref.attacks",
    ),
    # Pipeline components: only the harness writes GT and applies attacks.
    "data": ("mlfref.ground_truth", "mlfref.attacks"),
    "models": ("mlfref.ground_truth", "mlfref.attacks"),
    "provenance": ("mlfref.ground_truth", "mlfref.attacks"),
    "forensic": ("mlfref.ground_truth", "mlfref.attacks"),
    # Top-level pipeline modules (single files).
    "pipeline": ("mlfref.ground_truth", "mlfref.attacks", "mlfref.simulation"),
    "instrumentation": ("mlfref.ground_truth", "mlfref.attacks", "mlfref.simulation"),
}
# String literals the reconstruction engine must not contain (e.g. a path to GT storage,
# or a dynamic import of the GT module).
FORBIDDEN_LITERALS = re.compile(r"ground[_ ]?truth|\bgt_|gt_events", re.IGNORECASE)


def _module_name(path: Path) -> str:
    rel = path.relative_to(SRC).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _resolve(node: ast.ImportFrom, current: str, is_package: bool) -> str:
    if node.level == 0:
        return node.module or ""
    base = current.split(".") if is_package else current.split(".")[:-1]
    base = base[: len(base) - (node.level - 1)]
    return ".".join(base + ([node.module] if node.module else []))


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    current = _module_name(path)
    is_package = path.name == "__init__.py"
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            mod = _resolve(node, current, is_package)
            found.add(mod)
            found.update(f"{mod}.{alias.name}" for alias in node.names)
    return found


def _docstring_nodes(tree: ast.AST) -> set[int]:
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                ids.add(id(body[0].value))
    return ids


def _string_literals(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    skip = _docstring_nodes(tree)
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skip
    ]


def _py_files(package: str) -> list[Path]:
    single = PKG / f"{package}.py"
    if single.is_file():
        return [single]
    return sorted((PKG / package).rglob("*.py"))


def test_reconstruction_package_exists():
    """Guard against the scan passing vacuously."""
    assert _py_files("reconstruction"), "mlfref.reconstruction package not found"


@pytest.mark.parametrize("package", sorted(FORBIDDEN_IMPORTS))
def test_forbidden_imports(package):
    violations = []
    for path in _py_files(package):
        for imported in _imports(path):
            for forbidden in FORBIDDEN_IMPORTS[package]:
                if imported == forbidden or imported.startswith(forbidden + "."):
                    violations.append(f"{path.relative_to(SRC)} imports {imported}")
    assert not violations, "\n".join(violations)


def test_reconstruction_cannot_access_ground_truth_by_literal():
    violations = [
        f"{path.relative_to(SRC)}: {literal!r}"
        for path in _py_files("reconstruction")
        for literal in _string_literals(path)
        if FORBIDDEN_LITERALS.search(literal)
    ]
    assert not violations, "\n".join(violations)


def test_reconstruction_import_does_not_load_ground_truth():
    code = (
        "import sys; import mlfref.reconstruction as r; import pkgutil, importlib\n"
        "for m in pkgutil.walk_packages(r.__path__, 'mlfref.reconstruction.'):\n"
        "    importlib.import_module(m.name)\n"
        "bad = [m for m in sys.modules if m.startswith(('mlfref.ground_truth', "
        "'mlfref.evaluation', 'mlfref.attacks', 'mlfref.experiment_id'))]\n"
        "print(','.join(bad)); sys.exit(1 if bad else 0)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(SRC), **_base_env()},
    )
    assert result.returncode == 0, f"loaded forbidden modules: {result.stdout} {result.stderr}"


def test_ground_truth_separate():
    """GT runtime storage is a separate top-level directory, disjoint from evidence."""
    root = SRC.parent
    gt, evidence = (root / "ground_truth").resolve(), (root / "evidence").resolve()
    assert gt.is_dir() and evidence.is_dir()
    assert gt not in evidence.parents and evidence not in gt.parents and gt != evidence


def test_scanner_detects_violation(tmp_path, monkeypatch):
    """Self-test: the scanner really flags a forbidden relative import and literal."""
    fake_pkg = tmp_path / "mlfref" / "reconstruction"
    fake_pkg.mkdir(parents=True)
    (tmp_path / "mlfref" / "__init__.py").write_text("")
    (fake_pkg / "__init__.py").write_text("")
    bad = fake_pkg / "bad.py"
    bad.write_text("from ..ground_truth import recorder\nP = 'ground_truth/gt.sqlite'\n")
    monkeypatch.setattr(sys.modules[__name__], "SRC", tmp_path)
    assert "mlfref.ground_truth.recorder" in _imports(bad)
    assert any(FORBIDDEN_LITERALS.search(s) for s in _string_literals(bad))


def _base_env() -> dict[str, str]:
    import os

    keep = ("SYSTEMROOT", "PATH", "TEMP", "TMP", "HOME", "USERPROFILE")
    return {k: v for k, v in os.environ.items() if k.upper() in keep}
