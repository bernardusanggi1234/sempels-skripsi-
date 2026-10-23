"""CLI analisis taint, baseline sink-only, dan fakta parser lama."""
import argparse
import json
from pathlib import Path
from .engine.taint_engine import analyze_taint_file
from .parser import analyze_file


def main():
    parser = argparse.ArgumentParser(description='Analisis kandidat injeksi Flask tanpa menjalankan target.')
    parser.add_argument('file', type=Path)
    parser.add_argument('--format', choices=('text', 'json'), default='text')
    parser.add_argument('--mode', choices=('taint', 'sink-only', 'facts'), default='taint')
    parser.add_argument('--rules', type=Path, help='Khusus mode facts (parser legacy)')
    args = parser.parse_args()
    try:
        if args.rules and args.mode != 'facts':
            parser.error('--rules hanya untuk --mode facts; taint memakai src/source_sink.py')
        result = analyze_file(args.file, args.rules) if args.mode == 'facts' else analyze_taint_file(args.file)
    except (OSError, SyntaxError, ValueError) as error:
        parser.exit(2, f'Pemindaian gagal: {error}\n')
    data = result.to_dict()
    if args.mode == 'sink-only':
        data = {'filename': str(args.file), 'sink_inventory': list(result.sink_inventory), 'diagnostics': list(result.diagnostics)}
    if args.format == 'json':
        print(json.dumps(data, indent=2))
    elif args.mode == 'facts':
        for finding in result.findings:
            print(f'{args.file}:{finding.line} {finding.kind} {finding.category}')
    elif args.mode == 'sink-only':
        for sink in result.sink_inventory:
            print(f"{args.file}:{sink['line']} {sink['category']} {sink['sink']}")
    else:
        if result.coverage_issues:
            print('Analisis parsial: periksa batas cakupan pada diagnostics/coverage_issues; hasil kosong bukan bukti aman.')
        print(f'{result.vulnerable_count} kandidat | {result.review_count} perlu ditinjau | {result.sanitized_count} alur terbatas/binding')
        for flow in result.vulnerabilities:
            print(f'{args.file}:{flow.path[-1].line} [{flow.status}] {flow.vulnerability_type}: {flow.explanation}')
            print(' -> '.join(f'{s.kind}@{s.line}:{s.label}' for s in flow.path))
    if args.format == 'text' and args.mode != 'facts':
        for warning in result.diagnostics:
            print('CATATAN: ' + warning)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
