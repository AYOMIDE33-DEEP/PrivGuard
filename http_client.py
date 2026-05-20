from __future__ import annotations
import time
import requests
from dataclasses import dataclass
from typing import Optional, Dict, Any

@dataclass
class HttpResult:
    ok: bool
    status: int
    json: Optional[Dict[str, Any]]
    error: Optional[str]
    elapsed_ms: int

class HttpClient:
    def __init__(self, *, timeout_s: float = 8.0, retries: int = 1):
        self.timeout_s = timeout_s
        self.retries = max(0, int(retries))
        self.s = requests.Session()

    def get(self, url: str, *, headers=None, params=None) -> HttpResult:
        return self._do("GET", url, headers=headers, params=params, json=None)

    def post(self, url: str, *, headers=None, params=None, json=None) -> HttpResult:
        return self._do("POST", url, headers=headers, params=params, json=json)

    def _do(self, method: str, url: str, *, headers=None, params=None, json=None) -> HttpResult:
        last_err = None
        for attempt in range(self.retries + 1):
            t0 = time.time()
            try:
                r = self.s.request(
                    method, url,
                    headers=headers, params=params, json=json,
                    timeout=self.timeout_s
                )
                elapsed = int((time.time() - t0) * 1000)
                try:
                    payload = r.json()
                except Exception:
                    payload = None
                if 200 <= r.status_code < 300:
                    return HttpResult(True, r.status_code, payload, None, elapsed)
                last_err = f"upstream_status={r.status_code}"
                # retry on 429/5xx
                if r.status_code in (429, 500, 502, 503, 504) and attempt < self.retries:
                    time.sleep(0.15 * (attempt + 1))
                    continue
                return HttpResult(False, r.status_code, payload, last_err, elapsed)
            except Exception as e:
                elapsed = int((time.time() - t0) * 1000)
                last_err = f"{e.__class__.__name__}"
                if attempt < self.retries:
                    time.sleep(0.15 * (attempt + 1))
                    continue
                return HttpResult(False, 0, None, last_err, elapsed)
        return HttpResult(False, 0, None, last_err or "unknown", 0)