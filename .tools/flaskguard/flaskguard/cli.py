"""Installable project scanner. Target files are parsed, never imported."""
import argparse
import fnmatch
import json
import os
from pathlib import Path
import sys

from . import __version__
from src.engine import analyze_taint_file

IGNORED = {'.git', '.hg', '.svn', '__pycache__', 'node_modules', 'venv',
           '.venv', 'env', '.tox', '.mypy_cache', '.pytest_cache', 'build', 'dist'}


def linked(path):
    return path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction())


def excluded(path, base, patterns):
    relative = path.relative_to(base).as_posix()
    return any(fnmatch.fnmatchcase(relative, p) or fnmatch.fnmatchcase(path.name, p)
               for p in patterns)


def collect(targets, patterns, errors):
    files = set()
    for target in targets:
        path = Path(target).absolute()
        if linked(path):
            errors.append({'path': str(path), 'message': 'Target symlink/junction tidak didukung.'})
        elif path.is_file():
            if path.suffix != '.py':
                errors.append({'path': str(path), 'message': 'Target harus file .py atau direktori.'})
            elif not excluded(path, path.parent, patterns):
                files.add(path.resolve())
        elif path.is_dir():
            def onerror(error):
                errors.append({'path': str(error.filename), 'message': str(error)})
            for root, dirs, names in os.walk(path, followlinks=False, onerror=onerror):
                folder = Path(root)
                dirs[:] = sorted(d for d in dirs if d not in IGNORED
                                 and not d.startswith('.venv-')
                                 and not linked(folder / d)
                                 and not excluded(folder / d, path, patterns))
                for name in sorted(names):
                    item = folder / name
                    if item.suffix == '.py' and not linked(item) and not excluded(item, path, patterns):
                        files.add(item.resolve())
        else:
            errors.append({'path': str(path), 'message': 'Target tidak ditemukan atau tidak dapat dibaca.'})
    return sorted(files, key=str)


def render_text(report):
    summary = report['summary']
    lines = [f"FlaskGuard {__version__}: {summary['scanned_files']} file dianalisis | "
             f"{summary['candidate_findings']} kandidat | {summary['partial_files']} file parsial | "
             f"{summary['errors']} error | {summary['skipped_files']} dilewati"]
    for item in report['results']:
        for flow in item['vulnerabilities']:
            if flow['status'] not in ('vulnerable', 'needs_review'):
                continue
            line = flow['path'][-1]['line'] if flow['path'] else 0
            lines.append(f"{item['path']}:{line} [{flow['status']}] {flow['vulnerability_type']}")
            lines.append('  ' + flow['explanation'])
            lines.append('  ' + ' -> '.join(f"{s['kind']}@{s['line']}:{s['label']}" for s in flow['path']))
        for issue in item['coverage_issues']:
            lines.append(f"CAKUPAN {item['path']}:{issue['line']} {issue['reason']}")
    for item in report['errors']:
        lines.append(f"ERROR {item['path']}: {item['message']}")
    for item in report['skipped']:
        lines.append(f"DILEWATI {item['path']}: {item['reason']}")
    lines.append(report['interpretation'])
    return '\n'.join(lines)


def scan(args):
    errors, results, skipped = [], [], []
    files = collect(args.targets, args.exclude, errors)
    if args.output and args.output.resolve() in files:
        print('Output tidak boleh menimpa file target.', file=sys.stderr)
        return 2
    if not files and not errors:
        errors.append({'path': ', '.join(args.targets), 'message': 'Tidak ada file Python yang dipilih.'})
    for path in files:
        try:
            if path.stat().st_size > args.max_bytes:
                skipped.append({'path': str(path), 'reason': 'Melebihi --max-bytes.'})
                continue
            result = analyze_taint_file(path)
            results.append({'path': str(path), **result.to_dict()})
        except (OSError, ValueError, SyntaxError, RecursionError) as error:
            errors.append({'path': str(path), 'message': str(error)})
    candidates = sum(v['status'] in ('vulnerable', 'needs_review')
                     for item in results for v in item['vulnerabilities'])
    partial = sum(bool(item['coverage_issues']) for item in results)
    report = {
        'schema_version': 1, 'tool': {'name': 'FlaskGuard', 'version': __version__},
        'summary': {'selected_files': len(files), 'scanned_files': len(results),
                    'candidate_findings': candidates, 'partial_files': partial,
                    'errors': len(errors), 'skipped_files': len(skipped)},
        'results': results, 'errors': errors, 'skipped': skipped,
        'interpretation': 'Kandidat statis, bukan bukti eksploitasi. Hasil kosong bukan bukti aman; periksa cakupan analisis.',
    }
    output = json.dumps(report, indent=2, ensure_ascii=False) if args.format == 'json' else render_text(report)
    if args.output:
        try:
            args.output.write_text(output + '\n', encoding='utf-8')
        except OSError as error:
            print(f'Gagal menulis laporan: {error}', file=sys.stderr)
            return 2
    else:
        print(output)
    if errors or skipped or (args.strict and partial):
        return 2
    return 1 if args.error and candidates else 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog='flaskguard', description='Analisis statis AST/taint Flask tanpa menjalankan target.')
    parser.add_argument('--version', action='version', version=f'FlaskGuard {__version__}')
    commands = parser.add_subparsers(dest='command', required=True)
    scanner = commands.add_parser('scan', help='Pindai file atau folder Python secara rekursif.')
    scanner.add_argument('targets', nargs='*', default=['.'])
    formats = scanner.add_mutually_exclusive_group()
    formats.add_argument('--format', choices=('text', 'json'), default='text')
    formats.add_argument('--json', dest='format', action='store_const', const='json')
    scanner.add_argument('--output', '-o', type=Path)
    scanner.add_argument('--exclude', action='append', default=[], metavar='PATTERN', help='Pola fnmatch nama/path relatif target; dapat diulang.')
    scanner.add_argument('--error', '--fail-on-findings', action='store_true', help='Exit 1 jika ada kandidat temuan.')
    scanner.add_argument('--strict', action='store_true', help='Exit 2 jika cakupan analisis parsial.')
    scanner.add_argument('--max-bytes', type=int, default=1_000_000, help='Batas ukuran per file; default 1000000 byte.')
    commands.add_parser('gui', help='Buka GUI desktop (memerlukan Tk).')
    args = parser.parse_args(argv)
    if args.command == 'gui':
        from src.gui import main as gui_main
        gui_main()
        return 0
    if args.max_bytes < 1:
        parser.error('--max-bytes harus lebih dari nol.')
    return scan(args)
