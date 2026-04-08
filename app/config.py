from __future__ import annotations

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
ARTIFACTS_DIR = BASE_DIR / 'artifacts'
LOGS_DIR = BASE_DIR / 'logs'

# Rutas de artefactos ML
MODEL_PATH = Path(r'C:\Users\sergi\Documents\TFG\waf_hibrido\waf_hibrido\app\mnt\data\CNN_XSS_SQLi_99prtc.keras')
VECTORIZER_PATH = Path(r'C:\Users\sergi\Documents\TFG\waf_hibrido\waf_hibrido\app\mnt\data\vectorizer.joblib')

# Mapeo de clases del modelo
CLASS_MAPPING = {
    0: 'benign',
    1: 'xss',
    2: 'sqli',
}

# Backend dummy
DUMMY_BACKEND_URL = 'http://127.0.0.1:9000'

# Umbrales regex
# Umbrales regex
REGEX_BLOCK_THRESHOLD = 999999
REGEX_ML_THRESHOLD = 0
REGEX_LOG_THRESHOLD = 999999

# Umbrales ML
ML_BLOCK_THRESHOLD = 0.65
ML_LOG_THRESHOLD = 0.50

# Normalización
DOUBLE_URL_DECODE = True
MAX_FIELD_LENGTH = 4096
MAX_JOINED_LENGTH = 8192

# Cabeceras inspeccionables
SELECTED_HEADERS = {
    'user-agent',
    'referer',
    'x-forwarded-for',
    'x-real-ip',
    'content-type',
    'cookie',
}

# Logging
DECISION_LOG_PATH = LOGS_DIR / 'waf_decisions.jsonl'
