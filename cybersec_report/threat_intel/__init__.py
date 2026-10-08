"""Registry provider. Provider yang belum diimplementasikan (OTX, GreyNoise, ...) sengaja tidak
didaftarkan - UI menampilkannya sebagai 'belum tersedia', bukan pura-pura aktif."""
from .abuseipdb import AbuseIPDBProvider
from .virustotal import VirusTotalProvider

PROVIDERS = {"virustotal": VirusTotalProvider, "abuseipdb": AbuseIPDBProvider}
PLANNED_PROVIDERS = {"otx": "OTX_API_KEY", "greynoise": "GREYNOISE_API_KEY"}
