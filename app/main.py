from __future__ import annotations

from typing import Any

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from .config import DUMMY_BACKEND_URL
from .decision_engine import decide
from .logger_module import JSONLLogger
from .ml_engine import MLEngine
from .request_parser import build_request_context
from .regex_engine import evaluate_rules

app = FastAPI(title='Hybrid WAF', version='1.0.0')
logger = JSONLLogger()
ml_engine = None


@app.on_event('startup')
def startup() -> None:
    global ml_engine
    ml_engine = MLEngine()


@app.get('/health')
def health() -> dict[str, str]:
    return {'status': 'ok'}


@app.api_route('/{path:path}', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
async def waf_proxy(path: str, request: Request) -> Response:
    request_context = await build_request_context(request)
    payload = request_context['joined_payload']

    regex_result = evaluate_rules(payload)
    ml_result = None
    if regex_result['disposition'] == 'needs_ml':
        ml_result = ml_engine.predict(payload)

    final_decision = decide(regex_result, ml_result)

    log_record = {
        'client_ip': request_context['client_ip'],
        'method': request_context['method'],
        'path': request_context['path'],
        'payload': payload,
        'regex_result': regex_result,
        'ml_result': None if ml_result is None else {
            'predicted_index': ml_result.predicted_index,
            'predicted_label': ml_result.predicted_label,
            'confidence': ml_result.confidence,
            'probabilities': ml_result.probabilities,
        },
        'final_decision': final_decision,
    }
    logger.write(log_record)

    if final_decision['decision'] == 'block':
        return JSONResponse(
            status_code=403,
            content={
                'status': 'blocked',
                'reason': final_decision['reason'],
            },
        )

    upstream_response = await _forward_request(path, request)

    if final_decision['decision'] == 'log':
        upstream_response.headers['X-WAF-Decision'] = 'log'
        upstream_response.headers['X-WAF-Reason'] = final_decision['reason']
    else:
        upstream_response.headers['X-WAF-Decision'] = 'allow'
        upstream_response.headers['X-WAF-Reason'] = final_decision['reason']

    return upstream_response


async def _forward_request(path: str, request: Request) -> Response:
    body = await request.body()
    query_string = request.url.query
    target_url = f'{DUMMY_BACKEND_URL}/{path}' if path else DUMMY_BACKEND_URL
    if query_string:
        target_url = f'{target_url}?{query_string}'

    headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in {'host', 'content-length'}
    }

    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
        resp = await client.request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body,
            cookies=request.cookies,
        )

    excluded_headers = {'content-encoding', 'transfer-encoding', 'connection'}
    response_headers = {
        k: v for k, v in resp.headers.items() if k.lower() not in excluded_headers
    }
    return Response(
        content=resp.content,
        status_code=resp.status_code,
        headers=response_headers,
        media_type=resp.headers.get('content-type'),
    )
