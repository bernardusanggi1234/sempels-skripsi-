"""Evaluate validated labels at case/category/reference-sink units.

The scanner never executes target code. Label validation lives in validation/.
Unverified labels, failed analyses and incomplete reference sinks are excluded.
"""
import argparse
import hashlib
import json
from pathlib import Path
from .engine import analyze_taint_source
from .source_sink import SINKS

ROOT = Path(__file__).resolve().parents[1]


def metrics(counts):
    tp, fp, fn = counts['tp'], counts['fp'], counts['fn']
    return dict(counts, precision=tp/(tp+fp) if tp+fp else None,
                recall=tp/(tp+fn) if tp+fn else None,
                f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None)


def evaluate(dataset, split='development'):
    counts={mode:{cat:dict(tp=0,fp=0,fn=0,tn=0) for cat in SINKS} for mode in ('taint','sink-only')}
    rows=[]
    seen=set()
    excluded=dict(unverified=0,analysis_error=0,incomplete=0,stale_evidence=0)
    for case in dataset['cases']:
        if case['id'] in seen:
            raise ValueError('ID duplikat: '+case['id'])
        seen.add(case['id'])
        if case['split'] != split:
            continue
        if case['category'] not in SINKS:
            raise ValueError('Kategori tidak valid: '+case['id'])
        row=dict(id=case['id'],pair_id=case['pair_id'],category=case['category'],
                 label=case.get('label','unverified'),sink_line=case['sink_line'],
                 sink_column=case.get('sink_column'),outcomes={},predictions={},
                 rationale=case.get('label_reason',case.get('rationale','')))
        rows.append(row)
        if case.get('validation_status')!='validated' or case.get('label') not in {'vulnerable','safe'}:
            row['excluded']='unverified'
            excluded['unverified']+=1
            continue
        try:
            if 'code' in case:
                source=case['code']
                raw=source.encode('utf-8')
            else:
                path=(ROOT/case['file']).resolve()
                if not path.is_relative_to(ROOT):
                    raise ValueError('File kasus harus berada di workspace')
                raw=path.read_bytes()
                source=raw.decode('utf-8-sig')
            if not case.get('source_sha256') or hashlib.sha256(raw).hexdigest()!=case['source_sha256']:
                row['excluded']='stale_evidence'
                excluded['stale_evidence']+=1
                continue
            result=analyze_taint_source(source,case['id'])
        except Exception as error:
            row.update(excluded='analysis_error',error=f'{type(error).__name__}: {error}')
            excluded['analysis_error']+=1
            continue
        row.update(diagnostics=list(result.diagnostics),analysis_status=result.analysis_status)
        category,line,column=case['category'],case['sink_line'],case.get('sink_column')
        entry=case.get('entry_point')
        incomplete=[i for i in result.coverage_issues if i['line']<=line and (entry is None or i['entry_point'] in {entry,'<module>'})]
        if incomplete:
            row.update(excluded='incomplete',coverage_issues=incomplete)
            excluded['incomplete']+=1
            continue
        # Both modes use the same symbol resolver and execution-sink catalog.
        flows=[v for v in result.vulnerabilities if v.vulnerability_type==category and v.path[-1].line==line and (column is None or v.column==column) and v.status in {'vulnerable','needs_review'}]
        sinks=[v for v in result.sink_inventory if v['category']==category and v['line']==line and (column is None or v['column']==column)]
        row['predictions']={'taint':bool(flows),'sink-only':bool(sinks)}
        row['matched_flows']=[v.to_dict() for v in flows]
        row['rule_ids']=sorted({v['rule_id'] for v in sinks})
        for mode,predicted in row['predictions'].items():
            outcome=('tp' if predicted else 'fn') if case['label']=='vulnerable' else ('fp' if predicted else 'tn')
            counts[mode][category][outcome]+=1
            row['outcomes'][mode]=outcome
    if not rows:
        raise ValueError('Tidak ada kasus untuk split '+split)
    summary={}
    for mode,categories in counts.items():
        summary[mode]={'per_category':{c:metrics(n) for c,n in categories.items()},
                       'micro':metrics({k:sum(n[k] for n in categories.values()) for k in ('tp','fp','fn','tn')})}
    return {'split':split,'cases':len(rows),'evaluated_cases':len(rows)-sum(excluded.values()),'excluded':excluded,
            'unit':'case ID/category/reference sink line and column when present; duplicate flows collapsed',
            'caveat':'Only behavior-validated labels included. null means undefined. These development/feasibility cases are not independent final evaluation. Coverage after the reference sink does not invalidate that earlier sink.',
            'positive_policy':'vulnerable and needs_review reports count as positive candidates; framework-protected header candidates can therefore be false positives.',
            'summary':summary,'details':rows}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dataset',type=Path)
    parser.add_argument('--split',default='development')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    try:
        raw=args.dataset.read_bytes()
        report=evaluate(json.loads(raw),args.split)
        report['dataset_sha256']=hashlib.sha256(raw).hexdigest()
        for name,path in [('engine',Path(__file__).with_name('engine')/'taint_engine.py'),('catalog',Path(__file__).with_name('source_sink.py')),('evaluator',Path(__file__))]:
            report[name+'_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
        rendered=json.dumps(report,indent=2)
        if args.output:
            args.output.write_text(rendered+'\n',encoding='utf-8')
            print(args.output)
        else:
            print(rendered)
    except (OSError,ValueError,KeyError,SyntaxError) as error:
        parser.exit(2,f'Evaluasi gagal: {error}\n')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
