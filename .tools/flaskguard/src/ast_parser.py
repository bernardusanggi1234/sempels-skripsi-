"""Compatibility import; gunakan ``src.parser`` untuk implementasi utama."""
from .parser.scanner import AnalysisResult, AssignmentFact, EntryPoint, Finding, analyze_file, analyze_source

def scan_source(source: str, filename: str = "<string>") -> list[Finding]:
    return list(analyze_source(source, filename).findings)

def scan_file(path: str) -> list[Finding]:
    return list(analyze_file(path).findings)
