"""Basis provider Threat Intelligence: retry, exponential backoff, timeout, error terklasifikasi.
Provider baru (OTX, GreyNoise, dst) cukup subclass ThreatIntelProvider + daftarkan di __init__.py."""
import time


class ProviderError(Exception):
    """Kegagalan umum provider (timeout, 5xx, respons tak terduga)."""


class ProviderAuthError(ProviderError):
    """API key salah/ditolak (401/403). TIDAK di-retry."""


class ProviderRateLimited(ProviderError):
    """HTTP 429 setelah semua retry habis (rate limit per-menit yang tidak mereda)."""


class ProviderQuotaExceeded(ProviderError):
    """Kuota (harian/bulanan) provider habis. TIDAK di-retry: engine langsung beralih provider."""


QUOTA_KEYWORDS = ("quotaexceeded", "quota exceeded", "quota has been", "daily rate limit", "daily limit", "monthly limit")


class ThreatIntelProvider:
    name = "base"
    env_key = ""

    def __init__(self, api_key=None, session=None, timeout=15, max_retries=3, backoff=2.0, sleep=time.sleep,
                 max_retry_after=120):
        self.api_key = api_key
        self.max_retry_after, self.last_headers = max_retry_after, {}
        self.timeout, self.max_retries, self.backoff, self.sleep = timeout, max_retries, backoff, sleep
        if session is None:
            import requests
            session = requests.Session()
        self.session = session

    def is_configured(self):
        return bool(self.api_key)

    def query_ip(self, ip):
        raise NotImplementedError

    def remaining_quota(self):
        """Sisa kuota dari header respons terakhir bila provider mengirimnya, selain itu None."""
        return None

    def _get_json(self, url, headers=None, params=None):
        import requests
        last = ProviderError("unknown error")
        for attempt in range(self.max_retries + 1):
            wait = self.backoff * (2 ** attempt)
            try:
                resp = self.session.get(url, headers=headers, params=params, timeout=self.timeout)
            except (requests.Timeout, requests.ConnectionError) as e:
                last = ProviderError(f"{type(e).__name__}")
            else:
                code = resp.status_code
                self.last_headers = dict(getattr(resp, "headers", {}) or {})
                if code == 200:
                    try:
                        return resp.json()
                    except ValueError:
                        raise ProviderError("Respons bukan JSON valid")
                if code in (401, 403):
                    raise ProviderAuthError(f"HTTP {code}: API key ditolak")
                if code == 429:
                    try:
                        retry_after = float(resp.headers.get("Retry-After", 0))
                    except (TypeError, ValueError):
                        retry_after = 0.0
                    body = str(getattr(resp, "text", "")).lower()
                    # Kuota habis (bukan sekadar terlalu cepat): jangan retry, jangan buang request.
                    if any(k in body for k in QUOTA_KEYWORDS) or retry_after > self.max_retry_after:
                        raise ProviderQuotaExceeded("HTTP 429: kuota provider habis"
                                                    + (f" (Retry-After {int(retry_after)} dtk)" if retry_after else ""))
                    last = ProviderRateLimited("HTTP 429: rate limit provider")
                    wait = max(wait, retry_after)
                elif code >= 500:
                    last = ProviderError(f"HTTP {code}")
                else:
                    raise ProviderError(f"HTTP {code}: {str(resp.text)[:120]}")
            if attempt < self.max_retries:
                self.sleep(wait)
        raise last
