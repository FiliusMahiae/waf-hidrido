from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern

from .config import REGEX_BLOCK_THRESHOLD, REGEX_LOG_THRESHOLD, REGEX_ML_THRESHOLD


@dataclass(frozen=True)
class Rule:
    name: str
    family: str
    severity: str
    score: int
    pattern: Pattern[str]
    immediate_block: bool = False


RULES: list[Rule] = [
    Rule('xss_script_tag', 'xss', 'high', 10, re.compile(r'<\s*script\b', re.IGNORECASE), True),
    Rule('xss_js_scheme', 'xss', 'high', 9, re.compile(r'javascript\s*:', re.IGNORECASE), True),
    Rule('xss_event_handler', 'xss', 'high', 8, re.compile(r'on(?:error|load|click|mouseover|focus|submit)\s*=', re.IGNORECASE), True),
    Rule('xss_iframe', 'xss', 'medium', 4, re.compile(r'<\s*iframe\b', re.IGNORECASE)),
    Rule('xss_img_event', 'xss', 'medium', 4, re.compile(r'<\s*img\b[^>]*on\w+\s*=', re.IGNORECASE)),
    Rule('xss_svg_event', 'xss', 'medium', 4, re.compile(r'<\s*svg\b[^>]*on\w+\s*=', re.IGNORECASE)),
    Rule('xss_document_cookie', 'xss', 'medium', 3, re.compile(r'document\s*\.\s*cookie', re.IGNORECASE)),
    Rule('sqli_union_select', 'sqli', 'high', 10, re.compile(r'\bunion\b\s+\bselect\b', re.IGNORECASE), True),
    Rule('sqli_or_true', 'sqli', 'high', 9, re.compile(r"['\"]?\s*or\s+['\"]?1['\"]?=['\"]?1", re.IGNORECASE), True),
    Rule('sqli_information_schema', 'sqli', 'high', 8, re.compile(r'\binformation_schema\b', re.IGNORECASE), True),
    Rule('sqli_comment_sequence', 'sqli', 'medium', 4, re.compile(r'(?:--|#|/\*)', re.IGNORECASE)),
    Rule('sqli_sleep_benchmark', 'sqli', 'high', 8, re.compile(r'\b(?:sleep|benchmark)\s*\(', re.IGNORECASE), True),
    Rule('sqli_stacked_query', 'sqli', 'medium', 4, re.compile(r';\s*(?:drop|insert|update|delete|select)\b', re.IGNORECASE)),
    Rule('sqli_select_from', 'sqli', 'medium', 3, re.compile(r'\bselect\b.+\bfrom\b', re.IGNORECASE)),
]


def evaluate_rules(payload: str) -> dict:
    matches: list[dict] = []
    score = 0
    families: set[str] = set()
    immediate_block = False

    for rule in RULES:
        if rule.pattern.search(payload):
            matches.append(
                {
                    'name': rule.name,
                    'family': rule.family,
                    'severity': rule.severity,
                    'score': rule.score,
                    'immediate_block': rule.immediate_block,
                }
            )
            score += rule.score
            families.add(rule.family)
            if rule.immediate_block:
                immediate_block = True

    if immediate_block or score >= REGEX_BLOCK_THRESHOLD:
        disposition = 'block'
    elif score >= REGEX_ML_THRESHOLD:
        disposition = 'needs_ml'
    elif score >= REGEX_LOG_THRESHOLD:
        disposition = 'log'
    else:
        disposition = 'allow'

    return {
        'score': score,
        'matches': matches,
        'matched_families': sorted(families),
        'immediate_block': immediate_block,
        'disposition': disposition,
    }
