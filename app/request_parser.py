from __future__ import annotations

import json
from typing import Any

from fastapi import Request

from .config import SELECTED_HEADERS
from .normalizer import join_normalized_fields, normalize_value


async def _extract_body(request: Request) -> str:
    body_bytes = await request.body()
    if not body_bytes:
        return ''
    try:
        return body_bytes.decode('utf-8', errors='ignore')
    except Exception:
        return str(body_bytes)


async def build_request_context(request: Request) -> dict[str, Any]:
    body_text = await _extract_body(request)

    query_params = {k: v for k, v in request.query_params.multi_items()}
    cookies = dict(request.cookies)
    headers = {
        k.lower(): v
        for k, v in request.headers.items()
        if k.lower() in SELECTED_HEADERS
    }

    normalized_fields = {
        'method': normalize_value(request.method),
        'path': normalize_value(request.url.path),
        'query': normalize_value('&'.join(f'{k}={v}' for k, v in query_params.items())),
        'body': normalize_value(body_text),
        'cookies': normalize_value('; '.join(f'{k}={v}' for k, v in cookies.items())),
        'headers': normalize_value('; '.join(f'{k}={v}' for k, v in headers.items())),
    }

    return {
        'method': request.method,
        'path': request.url.path,
        'query_params': query_params,
        'headers': headers,
        'cookies': cookies,
        'body_text': body_text,
        'body_json': _safe_json_load(body_text),
        'normalized_fields': normalized_fields,
        'joined_payload': join_normalized_fields(normalized_fields),
        'client_ip': request.client.host if request.client else None,
    }


def _safe_json_load(body_text: str) -> Any:
    if not body_text:
        return None
    try:
        return json.loads(body_text)
    except Exception:
        return None
