from __future__ import annotations

import re
from urllib.parse import unquote_plus

from .config import DOUBLE_URL_DECODE, MAX_FIELD_LENGTH, MAX_JOINED_LENGTH

_WHITESPACE_RE = re.compile(r'\s+')


def normalize_value(value: str) -> str:
    if value is None:
        return ''
    text = str(value)[:MAX_FIELD_LENGTH]
    text = unquote_plus(text)
    if DOUBLE_URL_DECODE:
        text = unquote_plus(text)
    text = text.lower()
    text = _WHITESPACE_RE.sub(' ', text).strip()
    return text


def join_normalized_fields(fields: dict[str, str]) -> str:
    parts: list[str] = []
    for key, value in fields.items():
        if not value:
            continue
        parts.append(f'[{key}] {value}')
    return ' '.join(parts)[:MAX_JOINED_LENGTH]
