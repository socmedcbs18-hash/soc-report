"""Loader konfigurasi modul Cybersecurity Monthly Report.
DATA USER (snapshot periode, cache reputasi, output, device mapping, .env berisi API key) disimpan di
project/database/cybersec_report/ sehingga mengganti folder kode TIDAK menghapus data.
Semua behavior (alias kolom, scoring, struktur report, mapping device) dibaca dari
folder config/ - mengubah report TIDAK perlu mengubah kode Python."""
import json
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
PROJECT_DIR = BASE_DIR.parent
TEMPLATE_DIR = BASE_DIR / "templates"
ASSET_DIR = TEMPLATE_DIR / "assets"


def load_json(name):
    with open(CONFIG_DIR / name, "r", encoding="utf-8") as f:
        return json.load(f)


def load_settings():
    return load_json("settings.json")


def load_source_mapping():
    return load_json("source_mapping.json")


def load_scoring():
    return load_json("scoring.json")


def load_report_structure():
    return load_json("report_structure.json")


def load_attack_knowledge():
    return load_json("attack_knowledge.json").get("rules", [])


def load_asset_inventory():
    return load_json("asset_inventory.json").get("assets", {})


def data_dir():
    """Lokasi data user. Bisa dialihkan lewat env CYBERSEC_DATA_DIR (dipakai test)."""
    override = os.environ.get("CYBERSEC_DATA_DIR", "").strip()
    d = Path(override) if override else PROJECT_DIR / "database" / "cybersec_report"
    d.mkdir(parents=True, exist_ok=True)
    return d


def cache_dir():
    d = data_dir() / "cache"
    d.mkdir(parents=True, exist_ok=True)
    return d


def snapshot_dir():
    d = data_dir() / "snapshots"
    d.mkdir(parents=True, exist_ok=True)
    return d


def output_dir():
    d = data_dir() / "output"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _env_override_path():
    return data_dir() / "device_environment.json"


def load_device_environment():
    """Versi user (database/) menang atas default di config/."""
    user = _env_override_path()
    if user.exists():
        try:
            return json.loads(user.read_text(encoding="utf-8")).get("map", {})
        except ValueError:
            pass
    return load_json("device_environment.json").get("map", {})


def save_device_environment(mapping):
    """Simpan mapping devname -> environment dari UI ke database/. Nilai kosong dibuang."""
    clean = {str(k): str(v).strip() for k, v in mapping.items() if str(v).strip()}
    _env_override_path().write_text(json.dumps({"map": clean}, indent=2, ensure_ascii=False), encoding="utf-8")
    return clean


# ----------------------------------------------------------------------------- API key (.env)
KEY_NAMES = {"virustotal": "VT_API_KEY", "abuseipdb": "ABUSEIPDB_API_KEY"}


def env_files():
    """Urutan pencarian .env (yang pertama berisi nilai menang). Lokasi UTAMA: database/cybersec_report/.env"""
    seen, out = set(), []
    for p in (data_dir() / ".env", PROJECT_DIR / ".env", BASE_DIR / ".env", Path.cwd() / ".env"):
        rp = str(p.resolve())
        if rp not in seen:
            seen.add(rp)
            out.append(p)
    return out


def _parse_env_file(path):
    vals = {}
    try:
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            v = v.strip().strip('"').strip("'")
            if v:  # nilai kosong tidak boleh menutupi key yang diisi di file lain
                vals.setdefault(k.strip(), v)
    except OSError:
        pass
    return vals


def find_api_key(env_name, overrides=None):
    """Return (key, sumber). Prioritas: input UI (sesi) > variabel environment OS > file .env.
    File dibaca ulang setiap panggilan, jadi mengedit .env langsung berlaku tanpa restart."""
    if overrides and str(overrides.get(env_name, "")).strip():
        return str(overrides[env_name]).strip(), "input UI (sesi ini saja)"
    v = os.environ.get(env_name, "").strip()
    if v:
        return v, "environment OS"
    for p in env_files():
        if p.exists():
            vals = _parse_env_file(p)
            if env_name in vals:
                return vals[env_name], str(p)
    return None, None


def get_api_key(env_name, overrides=None):
    return find_api_key(env_name, overrides)[0]


def mask_key(key):
    return "" if not key else ("*" * 8 + key[-4:] if len(key) > 8 else "*" * len(key))


def save_env_keys(keys):
    """Tulis/perbarui KEY=value ke database/cybersec_report/.env (baris lain dipertahankan).
    Nilai kosong diabaikan (tidak menghapus key yang ada). Return path file."""
    path = data_dir() / ".env"
    keys = {k: str(v).strip() for k, v in keys.items() if str(v).strip()}
    lines = path.read_text(encoding="utf-8-sig").splitlines() if path.exists() else []
    done = set()
    for i, line in enumerate(lines):
        k = line.split("=", 1)[0].strip()
        if "=" in line and not line.strip().startswith("#") and k in keys:
            lines[i] = f"{k}={keys[k]}"
            done.add(k)
    lines += [f"{k}={v}" for k, v in keys.items() if k not in done]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
