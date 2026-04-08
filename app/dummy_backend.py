from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title='Dummy Backend', version='1.0.0')


@app.get('/health')
def health() -> dict:
    return {'status': 'ok'}


@app.api_route('/{path:path}', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
async def receive(path: str, request: Request):
    try:
        body = await request.body()
        try:
            decoded_body = body.decode('utf-8')
        except Exception:
            decoded_body = str(body)
        return JSONResponse(
            {
                'status': 'received',
                'path': '/' + path,
                'method': request.method,
                'query': request.url.query,
                'headers': {k: str(v) for k, v in request.headers.items()},
                'body': decoded_body,
            }
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "detail": str(e)
            }
        )
