"""Export auditable rules from the catalog consumed by the engine."""
import argparse
from dataclasses import asdict
import json
from pathlib import Path
from .source_sink import SOURCES, SINKS, NUMERIC_SANITIZERS

CASES = {
    'sink:DBAPI.Cursor.execute': ['sql_raw','sql_safe'],
    'sink:subprocess.run': ['command_raw','command_safe'],
    'sink:builtins.eval': ['code_raw','code_safe'],
    'sink:flask.render_template_string': ['ssti_raw','ssti_safe'],
    'sink:pymongo.collection.Collection.find': ['nosql_raw','nosql_safe'],
    'sink:werkzeug.datastructures.Headers.__setitem__': ['header_raw','header_safe'],
}


def export_catalog():
    rules=[]
    for spec in SOURCES.values():
        linked=['nosql_raw','nosql_safe'] if spec.name=='get_json' else [c for ids in CASES.values() for c in ids if not c.startswith('nosql')] if spec.name=='form' else []
        rules.append(dict(rule_id='source:'+spec.patterns[0],kind='source',categories=list(SINKS),
                          patterns=list(spec.patterns),function=spec.name,import_forms=['from flask import request [as alias]','import flask [as alias]'],
                          sensitive_parameters=[],conditions=['Flask import resolves and is not shadowed'],
                          effect='Mark returned/accessed values as untrusted; JSON may control structure.',
                          protection_preconditions=[],report_reason=spec.description,case_ids=linked,
                          limitations=['Only listed Flask sources; route parameters and helpers are not automatically sources.']))
    for category,specs in SINKS.items():
        for spec in specs:
            rule=asdict(spec)
            rule.update(rule_id=spec.rule_id,categories=[category],
                        import_forms=['import module [as alias]','from module import name [as alias]','Supported receiver constructor or explicit supported type annotation'],
                        effect='Preserve instruction-source state until execution' if spec.name in {'text','Template','from_string'} else 'Report candidate only when selected sensitive slots retain taint and category conditions match',
                        protection_preconditions=list(spec.conditions),
                        report_reason='Input reaches '+', '.join(p.role for p in spec.sensitive_parameters),
                        case_ids=CASES.get(spec.rule_id,[]),
                        limitations=['Resolver supports only TYPES/constructors in taint_engine.py; conditions are a semantic contract, not all automatically proved.',
                                     'An empty case_ids list means not exercised by the 12 feasibility cases.'])
            rules.append(rule)
    for name,categories in NUMERIC_SANITIZERS.items():
        rules.append(dict(rule_id='sanitizer:'+name,kind='sanitizer',categories=sorted(categories),patterns=[name],function=name,
                          import_forms=['Unshadowed builtin','import builtins [as alias]'],sensitive_parameters=[{'index':0,'role':'numeric input'}],
                          conditions=['Builtin identity resolves; conversion returns normally'],effect='Preserve provenance, restrict numeric representation; conversion exceptions are not a validated input.',
                          protection_preconditions=['No later concatenation of unconverted input','Does not establish business-level validation'],
                          report_reason='Numeric conversion constrains the instruction/structure alphabet.',case_ids=['command_safe','code_safe','header_safe'] if name.endswith('.int') else [],
                          limitations=['float is not exercised by the 12 cases','Custom converters and general allowlist guards are not recognized.']))
    transfers=[
        ('propagator:assignment','assignment',['x = y','x: T = y','x += y'],[c for ids in CASES.values() for c in ids], 'Evaluate RHS in current environment; overwrite target; prior copies retain prior state.'),
        ('protection:sql-binding','structural protection',['DBAPI.Cursor.execute(sql, parameters)'],['sql_safe'],'Only fixed SQL separates data from instructions; tainted SQL remains reportable.'),
        ('protection:template-context','structural protection',['flask.render_template_string(fixed_source, **context)'],['ssti_safe'],'Context values do not become template source.'),
        ('validator:json-scalar','shape restriction',['builtins.str'],['nosql_safe'],'Conversion makes an operator object a scalar in a fixed query field; not SQL/shell/code escaping.'),
    ]
    for id,kind,patterns,linked,effect in transfers:
        rules.append(dict(rule_id=id,kind=kind,categories=list(SINKS) if kind=='assignment' else ['SQL Injection'] if 'sql' in id else ['SSTI'] if 'template' in id else ['NoSQL Injection'],patterns=patterns,
                          function=patterns[0],import_forms=['Python syntax or resolved library identity'],sensitive_parameters=['See matched API rule; only selected slots carry instructions'],conditions=['Within a supported function and statement sequence'],
                          effect=effect,protection_preconditions=['All relevant input follows this path'],report_reason=effect,case_ids=linked,
                          limitations=['Unknown helpers do not clear taint; general validators are not inferred.']))
    return {'schema_version':1,'source':'src/source_sink.py consumed by engine; this export is documentation, not a separate rule loader',
            'cases':'validation/manifest.json','rules':rules}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    content=json.dumps(export_catalog(),indent=2)+'\n'
    if args.output:
        args.output.write_text(content,encoding='utf-8')
    else:
        print(content)

if __name__=='__main__':
    main()
