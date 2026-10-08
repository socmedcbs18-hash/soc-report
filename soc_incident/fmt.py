"""Format angka gaya Indonesia (titik ribuan, koma desimal). Fungsi murni."""
import math

MONTHS = ["Januari", "Februari", "Maret", "April", "Mei", "Juni", "Juli", "Agustus", "September", "Oktober", "November", "Desember"]


def _ok(x):
    return x is not None and not (isinstance(x, float) and math.isnan(x))


def num(x, d=0):
    if not _ok(x):
        return "–"
    s = f"{float(x):,.{d}f}"
    return s.replace(",", "§").replace(".", ",").replace("§", ".")


def pct(x, d=1):
    return "–" if not _ok(x) else num(x, d) + "%"


def minutes(x):
    if not _ok(x):
        return "–"
    x = float(x)
    if x < 1:
        return "< 1 mnt"
    if x < 120:
        return f"{num(x, 1)} mnt"
    if x < 2880:
        return f"{num(x / 60, 1)} jam"
    return f"{num(x / 1440, 1)} hari"


def month_name(m):
    return MONTHS[int(m) - 1]
