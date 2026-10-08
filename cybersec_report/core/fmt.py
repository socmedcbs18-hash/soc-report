"""Format angka. Locale 'id' (default, mengikuti deck contoh): 1.234 dan 61,45%."""


def fmt_int(x, locale="id"):
    s = f"{int(round(float(x))):,}"
    return s.replace(",", ".") if locale == "id" else s


def fmt_pct(x, decimals=2, locale="id"):
    s = f"{float(x):.{decimals}f}"
    return (s.replace(".", ",") if locale == "id" else s) + "%"
