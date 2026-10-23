"""Configurable Flask AST fact extractor; not a regex scanner."""
from __future__ import annotations
import ast
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

FindingKind = Literal["source", "sink", "sanitizer"]

@dataclass(frozen=True)
class Location:
    line: int; column: int; end_line: int; end_column: int

@dataclass(frozen=True)
class EntryPoint:
    name: str; kind: Literal["route", "class_based_view"]; location: Location; decorators: tuple[str, ...] = ()
    def to_dict(self) -> dict[str, object]: return asdict(self)

@dataclass(frozen=True)
class Finding:
    line: int; column: int; kind: FindingKind; category: str; variable: str | None; expression: str
    function: str; entry_point: str; callee: str; arguments: tuple[str, ...]; cwe: str; severity: str; location: Location
    def to_dict(self) -> dict[str, object]: return asdict(self)

@dataclass(frozen=True)
class AssignmentFact:
    targets: tuple[str, ...]; dependencies: tuple[str, ...]; expression: str; function: str; entry_point: str; location: Location
    def to_dict(self) -> dict[str, object]: return asdict(self)

@dataclass(frozen=True)
class AnalysisResult:
    filename: str; entry_points: tuple[EntryPoint, ...]; findings: tuple[Finding, ...]; assignments: tuple[AssignmentFact, ...]; imports: dict[str, str]
    source_code: str | None = None
    def to_dict(self) -> dict[str, object]:
        return {"filename": self.filename, "entry_points": [x.to_dict() for x in self.entry_points], "findings": [x.to_dict() for x in self.findings], "assignments": [x.to_dict() for x in self.assignments], "imports": self.imports}

class RuleSet:
    def __init__(self, sources: list[dict[str, str]], sinks: list[dict[str, str]], sanitizers: list[dict[str, str]]) -> None:
        self.sources, self.sinks, self.sanitizers = sources, sinks, sanitizers
    @classmethod
    def load(cls, path: str | Path | None = None) -> "RuleSet":
        rule_path = Path(path) if path else Path(__file__).with_name("default_rules.json")
        try: data = json.loads(rule_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error: raise ValueError(f"Konfigurasi rule tidak valid: {rule_path}") from error
        if any(not isinstance(data.get(k), list) for k in ("sources", "sinks", "sanitizers")): raise ValueError("Rule JSON harus memiliki sources, sinks, dan sanitizers berupa array")
        return cls(data["sources"], data["sinks"], data["sanitizers"])

class FlaskFactExtractor(ast.NodeVisitor):
    def __init__(self, rules: RuleSet, imports: dict[str, str], entries: dict[int, EntryPoint]) -> None:
        self.rules, self.imports, self.entries = rules, imports, entries
        self.findings: list[Finding] = []; self.assignments: list[AssignmentFact] = []
        self.entry: EntryPoint | None = None; self.targets: tuple[str, ...] = (); self.seen: set[tuple[int, int, str, str]] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        entry = self.entries.get(id(node))
        if entry is None: return  # Scope: hanya body Flask entry point.
        previous, self.entry = self.entry, entry
        for statement in node.body: self.visit(statement)
        self.entry = previous
    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:
        if self.entry:
            self._assignment(tuple(self._text(x) for x in node.targets), node.value, node)
    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if self.entry and node.value:
            self._assignment((self._text(node.target),), node.value, node)
    def _assignment(self, targets: tuple[str, ...], value: ast.AST, node: ast.AST) -> None:
        assert self.entry
        self.assignments.append(AssignmentFact(targets, tuple(self._names(value)), self._text(value), self.entry.name, self.entry.name, self._loc(node)))
        old, self.targets = self.targets, targets
        self.visit(value)
        self.targets = old

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if self.entry is None:
            return
        path = self._resolve(node)
        for rule in self.rules.sources:
            if path == rule["match"]: self._add(node, "source", rule, self._target, self._text(node), path, ())
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if self.entry is None:
            return
        path, arguments = self._resolve(node.func), tuple(self._text(x) for x in node.args)
        for kind, rules in (("source", self.rules.sources), ("sink", self.rules.sinks), ("sanitizer", self.rules.sanitizers)):
            for rule in rules:
                if self._matches(path, rule["match"]):
                    first = node.args[0] if node.args else None
                    variable = self._target if kind != "sink" else self._simple_name(first)
                    expression = self._text(node) if kind != "sink" else self._text(first)
                    self._add(node, kind, rule, variable, expression, path, arguments)
        # Hanya fakta binding pada SQL literal; bukan bukti sanitasi query dinamis.
        if self._matches(path, "*.execute") and len(node.args) >= 2 and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            self._add(node, "sanitizer", {"id": "parameterized_query", "cwe": "CWE-89", "severity": "info"}, self._simple_name(node.args[0]), self._text(node), path, arguments)
        self.generic_visit(node)

    def _add(self, node: ast.AST, kind: FindingKind, rule: dict[str, str], variable: str | None, expression: str, callee: str | None, arguments: tuple[str, ...]) -> None:
        assert self.entry
        loc, key = self._loc(node), (node.lineno, node.col_offset, kind, rule["id"])
        if key not in self.seen:
            self.seen.add(key); self.findings.append(Finding(loc.line, loc.column, kind, rule["id"], variable, expression, self.entry.name, self.entry.name, callee or "", arguments, rule.get("cwe", ""), rule.get("severity", ""), loc))

    @property
    def _target(self) -> str | None: return ", ".join(self.targets) or None
    def _resolve(self, node: ast.AST) -> str | None:
        raw = self._dotted(node)
        if not raw: return None
        head, *tail = raw.split("."); path = ".".join([self.imports.get(head, head), *tail])
        if path == "flask.request": return "request"
        return "request." + path.removeprefix("flask.request.") if path.startswith("flask.request.") else path
    @staticmethod
    def _matches(path: str | None, pattern: str) -> bool: return bool(path) and (path == pattern or pattern.startswith("*.") and path.endswith(pattern[1:]))
    @staticmethod
    def _dotted(node: ast.AST) -> str | None:
        if isinstance(node, ast.Name): return node.id
        if isinstance(node, ast.Attribute):
            parent = FlaskFactExtractor._dotted(node.value); return f"{parent}.{node.attr}" if parent else None
        return None
    @staticmethod
    def _text(node: ast.AST | None) -> str: return ast.unparse(node) if node else ""
    @staticmethod
    def _simple_name(node: ast.AST | None) -> str | None: return node.id if isinstance(node, ast.Name) else None
    @staticmethod
    def _names(node: ast.AST) -> list[str]: return sorted({x.id for x in ast.walk(node) if isinstance(x, ast.Name) and isinstance(x.ctx, ast.Load)})
    @staticmethod
    def _loc(node: ast.AST) -> Location: return Location(node.lineno, node.col_offset, getattr(node, "end_lineno", node.lineno), getattr(node, "end_col_offset", node.col_offset))

def _imports(tree: ast.AST) -> dict[str, str]:
    result: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names: result[item.asname or item.name.split(".")[0]] = item.name
        elif isinstance(node, ast.ImportFrom):
            for item in node.names:
                if item.name != "*": result[item.asname or item.name] = f"{node.module or ''}.{item.name}".strip(".")
    return result

def _entries(tree: ast.AST) -> dict[int, EntryPoint]:
    result: dict[int, EntryPoint] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            decorators = tuple(ast.unparse(x) for x in node.decorator_list)
            route_decorators = {"route", "get", "post", "put", "patch", "delete"}
            if any(isinstance(x, ast.Call) and isinstance(x.func, ast.Attribute) and x.func.attr in route_decorators for x in node.decorator_list): result[id(node)] = EntryPoint(node.name, "route", FlaskFactExtractor._loc(node), decorators)
        elif isinstance(node, ast.ClassDef) and any(ast.unparse(base).split(".")[-1] in {"MethodView", "View"} for base in node.bases):
            for method in node.body:
                if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)) and not method.name.startswith("_"): result[id(method)] = EntryPoint(f"{node.name}.{method.name}", "class_based_view", FlaskFactExtractor._loc(method))
    return result

def analyze_source(source: str, filename: str = "<string>", rules_path: str | Path | None = None) -> AnalysisResult:
    tree = ast.parse(source, filename=filename, type_comments=True); imports, entries = _imports(tree), _entries(tree)
    extractor = FlaskFactExtractor(RuleSet.load(rules_path), imports, entries); extractor.visit(tree)
    return AnalysisResult(filename, tuple(entries.values()), tuple(sorted(extractor.findings, key=lambda x: (x.line, x.column, x.kind))), tuple(extractor.assignments), dict(sorted(imports.items())), source)

def analyze_file(path: str | Path, rules_path: str | Path | None = None) -> AnalysisResult:
    file_path = Path(path)
    if file_path.suffix != ".py": raise ValueError(f"Hanya file .py yang didukung: {file_path}")
    return analyze_source(file_path.read_text(encoding="utf-8"), str(file_path), rules_path)
