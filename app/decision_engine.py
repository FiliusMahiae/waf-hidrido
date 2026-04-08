from __future__ import annotations

from .config import ML_BLOCK_THRESHOLD, ML_LOG_THRESHOLD


def decide(regex_result: dict, ml_result=None) -> dict:
    if regex_result['disposition'] == 'block':
        return {
            'decision': 'block',
            'reason': 'regex_high_confidence',
        }

    if regex_result['disposition'] == 'allow' and ml_result is None:
        return {
            'decision': 'allow',
            'reason': 'regex_clean',
        }

    if ml_result is None and regex_result['disposition'] == 'log':
        return {
            'decision': 'log',
            'reason': 'regex_low_confidence',
        }

    if ml_result is None:
        return {
            'decision': 'allow',
            'reason': 'regex_default',
        }

    if ml_result.predicted_label in {'xss', 'sqli'} and ml_result.confidence >= ML_BLOCK_THRESHOLD:
        return {
            'decision': 'block',
            'reason': f'ml_{ml_result.predicted_label}_high_confidence',
        }

    if ml_result.predicted_label in {'xss', 'sqli'} and ml_result.confidence >= ML_LOG_THRESHOLD:
        return {
            'decision': 'log',
            'reason': f'ml_{ml_result.predicted_label}_medium_confidence',
        }

    if regex_result['disposition'] in {'needs_ml', 'log'}:
        return {
            'decision': 'allow',
            'reason': 'ml_benign_or_low_confidence',
        }

    return {
        'decision': 'allow',
        'reason': 'default_allow',
    }
