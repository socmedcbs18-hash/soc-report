"""Ingestion: baca CSV / XLSX / XLS dengan deteksi delimiter dan encoding otomatis."""
import io
from pathlib import Path

import pandas as pd


class IngestionError(Exception):
    pass


def _to_bytes(file_or_path):
    if isinstance(file_or_path, (str, Path)):
        return Path(file_or_path).read_bytes(), Path(file_or_path).name
    name = getattr(file_or_path, "name", "uploaded")
    if hasattr(file_or_path, "getvalue"):
        return file_or_path.getvalue(), name
    return file_or_path.read(), name


def _decode(data):
    for enc in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return data.decode(enc), enc
        except UnicodeDecodeError:
            continue
    raise IngestionError("Encoding file tidak dikenali.")


def sniff_delimiter(text):
    """Pilih delimiter yang jumlahnya KONSISTEN di beberapa baris awal."""
    lines = [l for l in text.splitlines()[:10] if l.strip()]
    if not lines:
        raise IngestionError("File kosong.")
    best, best_score = ",", -1
    for d in [",", ";", "\t", "|"]:
        counts = [l.count(d) for l in lines]
        if counts[0] == 0:
            continue
        consistent = sum(1 for c in counts if c == counts[0])
        score = consistent * 100 + counts[0]
        if score > best_score:
            best, best_score = d, score
    return best


def read_table(file_or_path, filename=None, sheet_name=None):
    """Return (DataFrame bertipe string, meta). Semua nilai dibaca sebagai teks supaya
    tidak ada konversi diam-diam (mis. country 'NA' menjadi NaN)."""
    data, name = _to_bytes(file_or_path)
    name = filename or name
    ext = Path(name).suffix.lower()
    meta = {"filename": name, "format": ext.lstrip("."), "delimiter": None, "sheet": None, "sheets": []}
    try:
        if ext in (".csv", ".txt"):
            text, enc = _decode(data)
            delim = sniff_delimiter(text)
            df = pd.read_csv(io.StringIO(text), sep=delim, dtype=str, keep_default_na=False, na_values=[""])
            meta.update(delimiter=delim, encoding=enc)
        elif ext in (".xlsx", ".xlsm", ".xls"):
            engine = "xlrd" if ext == ".xls" else "openpyxl"
            try:
                xl = pd.ExcelFile(io.BytesIO(data), engine=engine)
            except ImportError:
                raise IngestionError("Format .xls membutuhkan paket 'xlrd'. Install dengan 'pip install xlrd' "
                                     "atau simpan file sebagai .xlsx.")
            meta["sheets"] = xl.sheet_names
            sheet = sheet_name if sheet_name in xl.sheet_names else xl.sheet_names[0]
            meta["sheet"] = sheet
            df = pd.read_excel(xl, sheet_name=sheet, dtype=str, keep_default_na=False, na_values=[""])
        else:
            raise IngestionError(f"Format file '{ext}' tidak didukung. Gunakan CSV, XLSX, atau XLS.")
    except IngestionError:
        raise
    except Exception as e:
        raise IngestionError(f"Gagal membaca file '{name}': {e}")
    df.columns = [str(c).strip() for c in df.columns]
    df = df.dropna(how="all").reset_index(drop=True)
    if df.empty:
        raise IngestionError("File tidak berisi baris data.")
    meta.update(rows=len(df), columns=list(df.columns))
    return df, meta
