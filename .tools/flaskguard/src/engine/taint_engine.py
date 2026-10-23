"""Ordered intraprocedural analysis. Target code is parsed, never executed."""
from __future__ import annotations

import ast
import re
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from src.parser import AnalysisResult, analyze_file, analyze_source
from src.parser.scanner import _entries
from src.source_sink import SOURCES, SINKS, NUMERIC_SANITIZERS

CWE = dict(zip(SINKS, ('CWE-89', 'CWE-78', 'CWE-94', 'CWE-1336', 'CWE-943', 'CWE-113')))
PATTERNS = {p: s for specs in SINKS.values() for s in specs for p in s.patterns}
TYPES = {
    'flask.Flask': 'flask.Flask', 'flask.Blueprint': 'flask.Blueprint',
    'sqlite3.Cursor': 'DBAPI.Cursor', 'sqlite3.Connection': 'DBAPI.Cursor',
    'pymongo.collection.Collection': 'pymongo.collection.Collection',
    'jinja2.Environment': 'jinja2.Environment', 'jinja2.Template': 'jinja2.Template',
    'jinja2.environment.Template': 'jinja2.Template',
    'flask.Response': 'flask.Response', 'flask.wrappers.Response': 'flask.Response',
    'werkzeug.wrappers.Response': 'flask.Response',
    'werkzeug.datastructures.Headers': 'werkzeug.datastructures.Headers',
    'sqlalchemy.engine.Connection': 'sqlalchemy.engine.Connection',
    'sqlalchemy.orm.Session': 'sqlalchemy.orm.Session',
}

@dataclass(frozen=True)
class FlowStep:
    label: str
    line: int
    kind: str

    def to_dict(self):
        return asdict(self)

@dataclass(frozen=True)
class Vulnerability:
    status: str
    vulnerability_type: str
    severity: str
    cwe: str
    entry_point: str
    source: str
    sink: str
    confidence: None
    path: tuple[FlowStep, ...]
    explanation: str
    column: int = 0
    rule_id: str = ''
    filename: str = ''
    sensitive_arguments: tuple[str, ...] = ()
    call_conditions: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    risk_kind: str = ''

    def to_dict(self):
        return asdict(self)

@dataclass(frozen=True)
class TaintAnalysisResult:
    parser_result: AnalysisResult
    vulnerabilities: tuple[Vulnerability, ...]
    diagnostics: tuple[str, ...] = ()
    sink_inventory: tuple[dict, ...] = ()
    coverage_issues: tuple[dict, ...] = ()
    source_inventory: tuple[dict, ...] = ()

    @property
    def analysis_status(self):
        return 'partial' if self.coverage_issues else 'complete_within_supported_model'

    @property
    def vulnerable_count(self):
        return sum(v.status == 'vulnerable' for v in self.vulnerabilities)

    @property
    def sanitized_count(self):
        return sum(v.status == 'sanitized' for v in self.vulnerabilities)

    @property
    def review_count(self):
        return sum(v.status == 'needs_review' for v in self.vulnerabilities)

    def to_dict(self):
        return {'analysis': self.parser_result.to_dict(),
                'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
                'diagnostics': list(self.diagnostics), 'sink_inventory': list(self.sink_inventory),
                'analysis_status': self.analysis_status, 'coverage_issues': list(self.coverage_issues),
                'source_inventory': list(self.source_inventory),
                'function_coverage': [dict(entry_point=e.name, line=e.location.line,
                    analysis_status='partial' if any(i['entry_point'] in (e.name, '<module>') for i in self.coverage_issues) else 'complete_within_supported_model',
                    issues=[i for i in self.coverage_issues if i['entry_point'] in (e.name, '<module>')]) for e in self.parser_result.entry_points],
                'interpretation': 'Kandidat statis, bukan bukti eksploitasi. confidence tidak dikalibrasi.'}

@dataclass(frozen=True)
class Value:
    paths: tuple[tuple[FlowStep, ...], ...] = ()
    symbol: str = ''
    shape: str = 'scalar'
    structure: bool = False
    safe_for: frozenset[str] = frozenset()
    elements: tuple[Value, ...] = ()


def combine(values):
    values = list(values)
    paths = tuple(dict.fromkeys(p for v in values for p in v.paths))
    tainted = [v for v in values if v.paths]
    safe = frozenset.intersection(*(v.safe_for for v in tainted)) if tainted else frozenset()
    return Value(paths, structure=any(v.structure for v in values), safe_for=safe)


class Tracker:
    def __init__(self):
        self.flows = []
        self.diagnostics = []
        self.inventory = []
        self.coverage_issues = []
        self.sources = []
        self.entry = '<module>'

    def source_value(self, label, node, **kwargs):
        item = dict(entry_point=self.entry, line=node.lineno, column=node.col_offset, source=label)
        if item not in self.sources:
            self.sources.append(item)
        return Value(((FlowStep(label, node.lineno, 'source'),),), **kwargs)

    def route_parameters(self, node, globals_env):
        """Only literal URL variables on resolved Flask/Blueprint decorators."""
        values = {}
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            symbol = self.symbol(decorator.func, globals_env)
            if symbol not in {f'{owner}.{method}' for owner in ('flask.Flask', 'flask.Blueprint')
                              for method in ('route', 'get', 'post', 'put', 'patch', 'delete')}:
                continue
            rule = decorator.args[0] if decorator.args else next((k.value for k in decorator.keywords if k.arg == 'rule'), None)
            if not isinstance(rule, ast.Constant) or not isinstance(rule.value, str):
                self.warn(decorator, 'Rule route dinamis belum di-resolve; parameter URL mungkin tidak lengkap.')
                continue
            defaults_node = next((k.value for k in decorator.keywords if k.arg == 'defaults'), None)
            fixed_defaults = set()
            if defaults_node is not None:
                try:
                    defaults = ast.literal_eval(defaults_node)
                    if isinstance(defaults, dict):
                        fixed_defaults = set(defaults)
                    else:
                        self.warn(decorator, 'defaults route bukan mapping literal yang didukung.')
                except (ValueError, TypeError, SyntaxError):
                    self.warn(decorator, 'defaults route dinamis belum di-resolve.')
            for token in re.findall(r'<([^<>]+)>', rule.value):
                converter, name = token.rsplit(':', 1) if ':' in token else ('string', token)
                if name in fixed_defaults:
                    continue
                kind = converter.split('(', 1)[0]
                value = self.source_value(f'flask.route.{name} ({kind})', decorator)
                if kind in ('int', 'float'):
                    # Numeric shape constrains instruction syntax, not executable/option selection.
                    safe = NUMERIC_SANITIZERS['builtins.' + kind] - {'Command Injection'}
                    value = replace(value, safe_for=safe,
                        paths=tuple(p + (FlowStep('route converter ' + kind, decorator.lineno, 'sanitizer'),) for p in value.paths))
                elif kind not in ('string', 'path', 'any', 'uuid'):
                    self.warn(decorator, 'Converter route kustom belum dimodelkan: ' + kind)
                values[name] = combine([values[name], value]) if name in values else value
        return values

    def warn(self, node, message, incomplete=True):
        warning = f'{self.entry}:{node.lineno}: {message}'
        if warning not in self.diagnostics:
            self.diagnostics.append(warning)
        issue = {'entry_point': self.entry, 'line': node.lineno, 'reason': message}
        if incomplete and issue not in self.coverage_issues:
            self.coverage_issues.append(issue)

    def symbol(self, node, env):
        if isinstance(node, ast.Name):
            return env.get(node.id, Value(symbol='builtins.' + node.id if node.id in {'eval', 'exec', 'int', 'float', 'str'} else '')).symbol
        if isinstance(node, ast.Attribute):
            base = self.symbol(node.value, env)
            if base == 'flask.Response' and node.attr == 'headers':
                return 'werkzeug.datastructures.Headers'
            return base + '.' + node.attr if base else ''
        return ''

    def expr(self, node, env):
        if node is None:
            return Value()
        if isinstance(node, ast.Name):
            return env.get(node.id, Value(symbol=self.symbol(node, env)))
        symbol = self.symbol(node, env)
        source = next((s for s in SOURCES.values() if symbol in s.patterns and s.access == 'attribute'), None)
        if source:
            json_source = source.name == 'json'
            return self.source_value(symbol, node, shape='json' if json_source else 'request_map', structure=json_source)
        if isinstance(node, ast.Constant):
            return Value()
        if isinstance(node, ast.Attribute):
            base = self.expr(node.value, env)
            return replace(base, symbol=symbol)
        if isinstance(node, ast.Subscript):
            base = self.expr(node.value, env)
            if base.symbol in {'pymongo.MongoClient', 'pymongo.synchronous.mongo_client.MongoClient'}:
                return Value(symbol='pymongo.database.Database')
            if base.symbol == 'pymongo.database.Database':
                return Value(symbol='pymongo.collection.Collection')
            return replace(base, symbol='', shape='json' if base.shape == 'json' else 'scalar')
        if isinstance(node, ast.Call):
            return self.call(node, env)
        if isinstance(node, ast.Dict):
            keys = [self.expr(k, env) for k in node.keys if k is not None]
            vals = [self.expr(v, env) for v in node.values]
            value = combine(keys + vals)
            script = any(isinstance(k, ast.Constant) and k.value == '$where' and v.paths for k, v in zip(node.keys, vals))
            return replace(value, shape='dict', structure=bool(script) or any(v.paths for v in keys) or any(v.structure for v in vals))
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            elements = tuple(self.expr(x, env) for x in node.elts)
            return replace(combine(elements), shape='sequence', elements=elements)
        if isinstance(node, (ast.Lambda, ast.ListComp, ast.DictComp, ast.SetComp, ast.GeneratorExp, ast.NamedExpr)):
            self.warn(node, 'Ekspresi di luar subset analisis; hasil tidak lengkap: ' + type(node).__name__)
        return replace(combine(self.expr(x, env) for x in ast.iter_child_nodes(node) if isinstance(x, ast.expr)), symbol='')

    def call(self, node, env):
        receiver = self.expr(node.func.value, env) if isinstance(node.func, ast.Attribute) else Value()
        symbol = (receiver.symbol + '.' + node.func.attr if receiver.symbol else '') if isinstance(node.func, ast.Attribute) else self.symbol(node.func, env)
        args = [self.expr(a, env) for a in node.args]
        kwargs = {k.arg: self.expr(k.value, env) for k in node.keywords}
        if any(k.arg is None for k in node.keywords) or any(isinstance(a, ast.Starred) for a in node.args):
            self.warn(node, 'Argumen unpacking belum di-resolve; posisi sink mungkin tidak lengkap.')
        all_values = args + list(kwargs.values())
        source = next((s for s in SOURCES.values() if symbol in s.patterns and s.access == 'call'), None)
        if source:
            return self.source_value(symbol, node, shape='json', structure=True)
        spec = PATTERNS.get(symbol)
        value = combine(all_values)
        if spec and spec.name in {'text', 'Template', 'from_string'}:
            # Constructors preserve only instruction/template source, not context.
            value = self.parameter(spec.sensitive_parameters[0], args, kwargs, receiver)
            return replace(value, symbol='jinja2.Template' if spec.category == 'SSTI' else 'sqlalchemy.TextClause')
        if spec:
            sensitive = combine(self.parameter(p, args, kwargs, receiver) for p in spec.sensitive_parameters)
            roles = {p.role: self.parameter(p, args, kwargs, receiver) for p in spec.sensitive_parameters}
            self.report(node, spec, symbol, sensitive, args, kwargs, roles)
        elif isinstance(node.func, ast.Attribute) and node.func.attr in {'execute', 'executemany', 'find', 'find_one', 'render', 'add', 'set', 'aggregate', 'update_one'}:
            self.warn(node, 'Receiver tidak ter-resolve untuk ' + ast.unparse(node.func) + '; tidak otomatis dianggap sink.')
        if symbol in NUMERIC_SANITIZERS:
            safe = NUMERIC_SANITIZERS[symbol]
            return replace(value, shape='scalar', structure=False, safe_for=safe,
                           paths=tuple(p + (FlowStep(symbol, node.lineno, 'sanitizer'),) for p in value.paths))
        if symbol == 'builtins.str':
            # Conversion prevents JSON operator objects, but does not escape SQL/code.
            return replace(value, shape='scalar', structure=False)
        if symbol in TYPES:
            # Response body is not its headers; object identity is retained separately.
            return Value(symbol=TYPES[symbol])
        if symbol == 'sqlite3.connect' or symbol == 'DBAPI.Cursor.cursor':
            return Value(symbol='DBAPI.Cursor')
        if symbol in {'pymongo.MongoClient', 'pymongo.synchronous.mongo_client.MongoClient'}:
            return Value(symbol='pymongo.MongoClient')
        if isinstance(node.func, ast.Attribute) and node.func.attr in {'get', 'getlist'} and receiver.paths:
            return replace(combine([receiver, value]), shape='json' if receiver.shape == 'json' else 'scalar')
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'format' and isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str):
            return value
        # Unknown helpers conservatively propagate taint; never assume sanitization.
        if not spec and value.paths and symbol not in {'builtins.str', 'markupsafe.escape', 'html.escape'}:
            self.warn(node, 'Retour fungsi tidak dianalisis; propagasi konservatif: ' + ast.unparse(node.func))
        return combine([receiver, value])

    @staticmethod
    def parameter(param, args, kwargs, receiver):
        if param.index is None:
            return receiver
        for name in param.keywords:
            if name in kwargs:
                return kwargs[name]
        return args[param.index] if param.index < len(args) else Value()

    def report(self, node, spec, symbol, sensitive, args, kwargs, roles=None):
        self.inventory.append({'entry_point': self.entry, 'line': node.lineno, 'column': node.col_offset,
                               'category': spec.category, 'sink': symbol, 'rule_id': spec.rule_id})
        status = 'vulnerable'
        roles = roles or {p.role: sensitive for p in spec.sensitive_parameters}
        affected = tuple(role for role, value in roles.items() if value.paths)
        reason = 'Input mencapai parameter sensitif: ' + ', '.join(affected)
        conditions = []
        risk_kind = 'shell_injection' if spec.category == 'Command Injection' else spec.category
        if spec.required_keywords:
            shell = next((k.value for k in getattr(node, 'keywords', []) if k.arg == 'shell'), None)
            shell_off = (shell is None and not any(k.arg is None for k in getattr(node, 'keywords', []))) or (isinstance(shell, ast.Constant) and shell.value is False)
            if shell_off:
                conditions.append('shell=False (explicit/default)')
                command = args[0] if args else kwargs.get('args', Value())
                executable = kwargs.get('executable', command.elements[0] if command.elements else command)
                arguments = combine(command.elements[1:]) if command.elements else Value()
                roles = {'executable': executable, 'arguments': arguments}
                sensitive = combine(roles.values())
                affected = tuple(role for role, value in roles.items() if value.paths)
                if not sensitive.paths:
                    return
                status = 'needs_review'
                risk_kind = 'executable_control' if executable.paths else 'argument_injection'
                reason = ('Input mengendalikan executable; periksa program yang dapat dipilih.' if executable.paths
                          else 'Input menjadi argumen program; periksa opsi/argument injection sesuai executable.')
                reason += ' Shell tidak diaktifkan; ini bukan bukti shell injection.'
            elif not (isinstance(shell, ast.Constant) and shell.value is True):
                status = 'needs_review'
                reason += '; nilai shell belum dapat dipastikan'
                conditions.append('shell=unknown')
            else:
                conditions.append('shell=True')
                command = args[0] if args else kwargs.get('args', Value())
                if command.elements:
                    sensitive = command.elements[0]
                    roles = {'shell_command': sensitive}
                    affected = ('shell_command',) if sensitive.paths else ()
                    self.warn(node, 'shell=True dengan sequence: elemen pertama dimodelkan sebagai source shell (POSIX); semantik platform/argumen shell tambahan perlu diperiksa.')
            if not shell_off and kwargs.get('executable', Value()).paths:
                roles = dict(roles, executable=kwargs['executable'])
                sensitive = combine(roles.values())
        if spec.category == 'NoSQL Injection' and not sensitive.structure:
            return
        if spec.category == 'Header Injection':
            status = 'needs_review'
            reason += '; validasi CR/LF framework perlu diperiksa, bukan bukti response splitting'
        if not sensitive.paths and spec.category == 'SQL Injection' and spec.name in {'execute', 'executemany'}:
            bound = combine(args[1:] + [v for k, v in kwargs.items() if k not in {'statement'}])
            if bound.paths:
                sensitive, status = bound, 'sanitized'
                roles = {'bound_values': bound}
                affected = ('bound_values',)
                reason = 'Input hanya pada nilai binding; teks SQL tidak mengandung taint yang terlacak.'
        if spec.category in sensitive.safe_for and not (spec.required_keywords and 'shell=False (explicit/default)' in conditions):
            status = 'sanitized'
            reason = 'Konversi numerik terdaftar membatasi karakter/struktur input pada alur ini.'
        for path in sensitive.paths:
            path_roles = tuple(role for role, value in roles.items() if path in value.paths)
            path_reason = reason
            path_status, path_risk = status, risk_kind
            if spec.required_keywords and path_roles == ('executable',):
                path_status, path_risk = 'needs_review', 'executable_control'
                path_reason = 'Input mengendalikan executable; periksa program/shell yang dapat dipilih.'
            if spec.category == 'Header Injection' and status != 'sanitized':
                path_reason = 'Input mencapai ' + ', '.join(path_roles) + '; validasi CR/LF framework perlu diperiksa, bukan bukti response splitting'
            flow = Vulnerability(path_status, spec.category, 'info' if path_status == 'sanitized' else 'high', CWE[spec.category],
                                 self.entry, path[0].label, symbol, None,
                                 path + (FlowStep(ast.unparse(node), node.lineno, 'sink'),), path_reason, node.col_offset, spec.rule_id,
                                 sensitive_arguments=path_roles or affected, call_conditions=tuple(conditions) + spec.conditions,
                                 risk_kind=path_risk)
            if flow not in self.flows:
                self.flows.append(flow)

    def assign(self, target, value, env, node):
        if isinstance(target, ast.Name):
            paths = tuple(p if len(p) == 1 and p[0].line == node.lineno else p + (FlowStep(target.id, node.lineno, 'assignment'),) for p in value.paths)
            env[target.id] = replace(value, paths=paths)
        elif isinstance(target, ast.Subscript):
            receiver = self.expr(target.value, env)
            if receiver.symbol == 'werkzeug.datastructures.Headers':
                spec = PATTERNS[receiver.symbol + '.__setitem__']
                key = self.expr(target.slice, env)
                self.report(node, spec, receiver.symbol + '.__setitem__', combine([key, value]), [], {}, {'header_name': key, 'header_value': value})
            else:
                self.warn(node, 'Mutasi container belum dilacak secara field-sensitive.')
                if isinstance(target.value, ast.Name):
                    env[target.value.id] = combine([receiver, value])
        else:
            self.warn(node, 'Target assignment belum didukung: ' + ast.unparse(target))

    @staticmethod
    def merge_envs(environments):
        merged = {}
        for key in set().union(*(e.keys() for e in environments)):
            values = [e.get(key, Value()) for e in environments]
            first = values[0]
            merged[key] = replace(combine(values),
                symbol=first.symbol if all(v.symbol == first.symbol for v in values) else '',
                shape=first.shape if all(v.shape == first.shape for v in values) else 'unknown',
                elements=first.elements if all(v.elements == first.elements for v in values) else ())
        return merged

    def merge_outcomes(self, outcomes):
        return [(kind, self.merge_envs([env for k, env in outcomes if k == kind]))
                for kind in dict.fromkeys(k for k, _ in outcomes)]

    @staticmethod
    def can_raise(node):
        # Expression evaluation can fail before an assignment commits. Nested
        # suites are handled by block_flow, not by walking their statements here.
        expressions = [child for child in ast.iter_child_nodes(node) if isinstance(child, ast.expr)]
        return isinstance(node, (ast.Import, ast.ImportFrom)) or any(
            isinstance(item, (ast.Call, ast.Subscript, ast.Attribute, ast.BinOp, ast.UnaryOp, ast.Compare))
            for expr in expressions for item in ast.walk(expr))

    def try_flow(self, node, env):
        self.warn(node, 'Exception flow konservatif: titik kegagalan, tipe exception, dan kondisi handler tidak dibuktikan; efek samping pemanggilan tidak dimodelkan.')
        failures = []
        body = self.block_flow(node.body, env.copy(), failures)
        exceptional = failures + [state for kind, state in body if kind == 'raise']
        outcomes = [(kind, state) for kind, state in body if kind not in ('normal', 'raise')]
        for kind, state in body:
            if kind == 'normal':
                else_failures = []
                outcomes.extend(self.block_flow(node.orelse, state, else_failures))
                outcomes.extend(('raise', e) for e in else_failures)
        if exceptional:
            incoming = self.merge_envs(exceptional)
            catches_all = False
            for handler in node.handlers:
                state = incoming.copy()
                if handler.name:
                    state[handler.name] = Value()
                handler_failures = []
                handled = self.block_flow(handler.body, state, handler_failures)
                handled.extend(('raise', e) for e in handler_failures)
                for kind, state in handled:
                    if handler.name:
                        state.pop(handler.name, None)
                    outcomes.append((kind, state))
                if handler.type is None:
                    catches_all = True
                    break
            if not catches_all:
                outcomes.append(('raise', incoming))
        # Finally runs for each distinct pending outcome. A normal completion
        # resumes that outcome; return/raise inside finally replaces it.
        final = []
        for pending, state in self.merge_outcomes(outcomes):
            failures = []
            for kind, end in self.block_flow(node.finalbody, state, failures):
                final.append((pending if kind == 'normal' else kind, end))
            final.extend(('raise', e) for e in failures)
        return self.merge_outcomes(final)

    def block(self, statements, env):
        outcomes = self.block_flow(statements, env)
        normal = [state for kind, state in outcomes if kind == 'normal']
        if normal:
            merged = self.merge_envs(normal)
            env.clear()
            env.update(merged)
        return bool(normal)

    def block_flow(self, statements, env, exceptions=None):
        exits = []
        for node in statements:
            if exceptions is not None and not isinstance(node, ast.Try) and self.can_raise(node):
                exceptions.append(env.copy())
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.Import):
                    for a in node.names:
                        env[a.asname or a.name.split('.')[0]] = Value(symbol=a.name if a.asname else a.name.split('.')[0])
                else:
                    for a in node.names:
                        env[a.asname or a.name] = Value(symbol=f'{node.module}.{a.name}')
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = self.expr(node.value, env)
                if isinstance(node, ast.AnnAssign) and node.value is None:
                    annotation = self.symbol(node.annotation, env)
                    value = env.get(node.target.id, Value()) if isinstance(node.target, ast.Name) else Value()
                    if not value.symbol and annotation in TYPES:
                        value = replace(value, symbol=TYPES[annotation])
                for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                    self.assign(target, value, env, node)
            elif isinstance(node, ast.AugAssign):
                self.assign(node.target, combine([self.expr(node.target, env), self.expr(node.value, env)]), env, node)
            elif isinstance(node, ast.Expr):
                self.expr(node.value, env)
            elif isinstance(node, (ast.Return, ast.Raise)):
                self.expr(node.value if isinstance(node, ast.Return) else node.exc, env)
                return self.merge_outcomes(exits + [('return' if isinstance(node, ast.Return) else 'raise', env.copy())])
            elif isinstance(node, ast.If):
                self.expr(node.test, env)
                if isinstance(node.test, ast.Constant):
                    branches = [node.body if node.test.value else node.orelse]
                else:
                    branches = [node.body, node.orelse]
                outcomes = [outcome for branch in branches for outcome in self.block_flow(branch, env.copy(), exceptions)]
                exits.extend((kind, state) for kind, state in outcomes if kind != 'normal')
                normal = [state for kind, state in outcomes if kind == 'normal']
                if not normal:
                    return self.merge_outcomes(exits)
                merged = self.merge_envs(normal)
                env.clear()
                env.update(merged)
                self.warn(node, 'Cabang digabung konservatif; kelayakan kondisi/validasi guard tidak dibuktikan.', incomplete=False)
            elif isinstance(node, ast.Try):
                outcomes = self.try_flow(node, env)
                exits.extend((kind, state) for kind, state in outcomes if kind != 'normal')
                normal = [state for kind, state in outcomes if kind == 'normal']
                if not normal:
                    return self.merge_outcomes(exits)
                merged = self.merge_envs(normal)
                env.clear()
                env.update(merged)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                env[node.name] = Value()
            elif isinstance(node, ast.Pass):
                pass
            else:
                self.warn(node, 'Pernyataan di luar subset: ' + type(node).__name__ + '; sisa fungsi tidak dianalisis.')
                return self.merge_outcomes(exits + [('unsupported', env.copy())])
        return self.merge_outcomes(exits + [('normal', env.copy())])


def analyze_taint_result(result: AnalysisResult) -> TaintAnalysisResult:
    if result.source_code is None:
        raise ValueError('Engine memerlukan source_code dari analyze_source/analyze_file, bukan fakta tanpa urutan AST.')
    tree = ast.parse(result.source_code, filename=result.filename)
    tracker = Tracker()
    globals_env = {}
    # Only declarations and straight-line initialization establish global symbols.
    tracker.block([n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom, ast.Assign, ast.AnnAssign, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))], globals_env)
    tracker.flows.clear()
    tracker.inventory.clear()
    tracker.sources.clear()
    entries = _entries(tree)
    if not entries:
        tracker.coverage_issues.append({'entry_point': '<module>', 'line': 0, 'reason': 'Tidak ada entry point yang dikenali.'})
    for node in ast.walk(tree):
        if id(node) not in entries:
            continue
        tracker.entry = entries[id(node)].name
        env = globals_env.copy()
        # Python function locals shadow globals even before their first assignment.
        def locals_in(statements):
            for statement in statements:
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    yield statement.name
                    continue
                for child in ast.iter_child_nodes(statement):
                    if isinstance(child, ast.stmt):
                        yield from locals_in([child])
                    elif isinstance(child, ast.expr):
                        for item in ast.walk(child):
                            if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Store):
                                yield item.id
        for name in locals_in(node.body):
            env[name] = Value()
        for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs + [a for a in (node.args.vararg, node.args.kwarg) if a]:
            annotation = tracker.symbol(arg.annotation, globals_env) if arg.annotation else ''
            env[arg.arg] = Value(symbol=TYPES.get(annotation, ''))
        parameters = tracker.route_parameters(node, globals_env)
        for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
            if arg.arg in parameters:
                env[arg.arg] = parameters[arg.arg]
        tracker.block(node.body, env)
    inventory = tuple(dict(t) for t in dict.fromkeys(tuple(x.items()) for x in tracker.inventory))
    flows = tuple(replace(flow, filename=result.filename,
        limitations=tuple(i['reason'] for i in tracker.coverage_issues if i['entry_point'] in (flow.entry_point, '<module>')))
        for flow in tracker.flows)
    return TaintAnalysisResult(result, flows, tuple(tracker.diagnostics), inventory, tuple(tracker.coverage_issues), tuple(tracker.sources))


def analyze_taint_source(source: str, filename: str = '<string>') -> TaintAnalysisResult:
    return analyze_taint_result(analyze_source(source, filename))


def analyze_taint_file(path: str | Path, rules_path: str | Path | None = None) -> TaintAnalysisResult:
    if rules_path is not None:
        raise ValueError('--rules hanya didukung mode facts; engine memakai katalog src/source_sink.py.')
    return analyze_taint_result(analyze_file(path))
