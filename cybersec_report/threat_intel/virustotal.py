from .base import ThreatIntelProvider


class VirusTotalProvider(ThreatIntelProvider):
    name = "virustotal"
    env_key = "VT_API_KEY"
    URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    def query_ip(self, ip):
        data = self._get_json(self.URL.format(ip=ip), headers={"x-apikey": self.api_key})
        attr = (data or {}).get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {}) or {}
        return {"malicious": int(stats.get("malicious", 0)), "suspicious": int(stats.get("suspicious", 0)),
                "harmless": int(stats.get("harmless", 0)), "undetected": int(stats.get("undetected", 0)),
                "reputation": attr.get("reputation"), "country": attr.get("country"), "as_owner": attr.get("as_owner")}
