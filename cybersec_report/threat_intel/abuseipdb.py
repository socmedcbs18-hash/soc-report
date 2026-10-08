from .base import ThreatIntelProvider


class AbuseIPDBProvider(ThreatIntelProvider):
    name = "abuseipdb"
    env_key = "ABUSEIPDB_API_KEY"
    URL = "https://api.abuseipdb.com/api/v2/check"

    def query_ip(self, ip):
        data = self._get_json(self.URL, headers={"Key": self.api_key, "Accept": "application/json"},
                              params={"ipAddress": ip, "maxAgeInDays": 90})
        d = (data or {}).get("data", {})
        return {"abuseConfidenceScore": int(d.get("abuseConfidenceScore", 0) or 0),
                "countryCode": d.get("countryCode"), "isp": d.get("isp"), "domain": d.get("domain"),
                "totalReports": int(d.get("totalReports", 0) or 0), "lastReportedAt": d.get("lastReportedAt"),
                "usageType": d.get("usageType"), "numDistinctUsers": d.get("numDistinctUsers")}

    def remaining_quota(self):
        try:
            return int(self.last_headers.get("X-RateLimit-Remaining"))
        except (TypeError, ValueError):
            return None
