# WAF híbrido regex-first + red neuronal

Prototipo experimental de WAF que intercepta peticiones HTTP en tiempo real, evalúa patrones regex para XSS/SQLi y, en casos ambiguos, deriva la decisión a un modelo neuronal previamente entrenado.

## Estructura

- `app/main.py`: proxy WAF principal
- `app/dummy_backend.py`: backend de pruebas
- `app/request_parser.py`: parsing de la petición
- `app/normalizer.py`: normalización y unión de campos
- `app/regex_engine.py`: reglas y scoring
- `app/ml_engine.py`: carga de vectorizador y modelo Keras
- `app/decision_engine.py`: lógica híbrida final
- `app/logger_module.py`: logging JSONL
- `app/config.py`: configuración global

## Requisitos

Coloca estos artefactos en `/mnt/data` o ajusta `app/config.py`:

- `CNN_XSS_SQLi_99prtc.keras`
- `vectorizer.joblib`

## Instalación

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Ejecución

### 1. Lanzar el backend dummy

```bash
uvicorn app.dummy_backend:app --host 0.0.0.0 --port 9000
```

### 2. Lanzar el WAF

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Pruebas rápidas

Petición legítima:

```bash
curl "http://127.0.0.1:8000/search?q=producto"
```

XSS obvio:

```bash
curl "http://127.0.0.1:8000/test?msg=<script>alert(1)</script>"
```

SQLi:

```bash
curl "http://127.0.0.1:8000/login?user=admin&pass=' OR 1=1 --"
```

## Logging

Las decisiones se guardan en:

`logs/waf_decisions.jsonl`

Cada entrada incluye:

- timestamp
- payload normalizado
- coincidencias regex
- resultado ML (si aplica)
- decisión final

## Umbrales

Por defecto:

- regex de alta confianza o score >= 8 → `BLOCK`
- score regex entre 3 y 7 → consulta ML
- ML malicioso con probabilidad >= 0.90 → `BLOCK`
- ML malicioso con probabilidad entre 0.75 y 0.90 → `LOG`
- resto → `ALLOW`
