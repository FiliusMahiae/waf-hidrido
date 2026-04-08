from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import DECISION_LOG_PATH


class JSONLLogger:
    def __init__(self, path: Path = DECISION_LOG_PATH):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, record: dict[str, Any]) -> None:
        enriched = {
            'timestamp_utc': datetime.now(timezone.utc).isoformat(),
            **record,
        }
        with self.path.open('a', encoding='utf-8') as f:
            f.write(json.dumps(enriched, ensure_ascii=False) + '\n')
