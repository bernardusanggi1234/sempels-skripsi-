"""Project results for the desktop UI, retaining each file's source snapshot."""
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

from .cli import collect
from src.engine import analyze_taint_file


@dataclass
class ProjectResult:
    target: str
    results: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    skipped: list = field(default_factory=list)

    @property
    def vulnerabilities(self):
        return tuple(flow for result in self.results for flow in result.vulnerabilities)

    @property
    def parser_result(self):
        return SimpleNamespace(filename=self.target, source_code='', entry_points=[
            entry for result in self.results for entry in result.parser_result.entry_points])

    @property
    def vulnerable_count(self):
        return sum(r.vulnerable_count for r in self.results)

    @property
    def review_count(self):
        return sum(r.review_count for r in self.results)

    @property
    def sanitized_count(self):
        return sum(r.sanitized_count for r in self.results)

    @property
    def coverage_issues(self):
        issues = [dict(item, reason=f"{r.parser_result.filename}: {item['reason']}")
                  for r in self.results for item in r.coverage_issues]
        issues.extend(dict(line=0, entry_point='<file>', reason=f"{item['path']}: {item.get('message', item.get('reason'))}")
                      for item in self.errors + self.skipped)
        return issues

    @property
    def diagnostics(self):
        return tuple(f'{r.parser_result.filename}: {note}' for r in self.results for note in r.diagnostics)

    @property
    def analysis_status(self):
        return 'partial' if self.coverage_issues else 'complete_within_supported_model'

    def owner(self, flow):
        return next(r for r in self.results if any(v is flow for v in r.vulnerabilities))

    def to_dict(self):
        return dict(schema_version=1, target=self.target, analysis_status=self.analysis_status,
                    summary=dict(scanned_files=len(self.results), errors=len(self.errors),
                                 skipped_files=len(self.skipped),
                                 partial_files=sum(bool(r.coverage_issues) for r in self.results),
                                 candidate_findings=self.vulnerable_count + self.review_count),
                    results=[dict(path=r.parser_result.filename, **r.to_dict()) for r in self.results],
                    errors=self.errors, skipped=self.skipped)


def scan_project(target, progress=None):
    report = ProjectResult(str(target))
    files = collect([str(target)], [], report.errors)
    if not files and not report.errors:
        report.errors.append(dict(path=str(target), message='Tidak ada file .py yang dipilih.'))
    for index, path in enumerate(files, 1):
        if progress:
            progress(index, len(files), path.name)
        try:
            if path.stat().st_size > 1_000_000:
                report.skipped.append(dict(path=str(path), reason='Ukuran melebihi 1 MB.'))
                continue
            report.results.append(analyze_taint_file(path))
        except Exception as error:
            report.errors.append(dict(path=str(path), message=str(error) or type(error).__name__))
    return report
