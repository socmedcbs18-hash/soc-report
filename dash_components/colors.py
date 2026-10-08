"""
Shared color constants untuk dash_app - SENGAJA DUPLIKASI (bukan import)
dari definisi di app.py Streamlit, sesuai prinsip "module isolation: setiap
modul self-contained, tidak boleh import dari modul lain" yang sudah
disepakati sebelumnya - dash_app harus bisa jalan independen tanpa
menyentuh/tergantung app.py Streamlit sama sekali.
"""

PALETTE = ["#1F4E78", "#4A90D9", "#7FB3E8", "#F0B429", "#D9534F", "#5CB85C", "#9B59B6", "#95A5A6"]

SEMANTIC_COLORS = {
    "critical": "#C0392B", "p0-critical": "#C0392B", "breach - reported": "#C0392B",
    "high": "#E67E22", "p1-high": "#E67E22",
    "medium": "#F0B429", "p2-medium": "#F0B429", "acceptable": "#F0B429", "review": "#F0B429",
    "low": "#2E7D32", "p3-low": "#2E7D32", "healthy": "#2E7D32", "prevented": "#2E7D32",
    "noise": "#D9534F", "dormant": "#95A5A6", "unknown": "#95A5A6",
}

CATEGORY_COLORS = {
    "infrastructure": "#4285F4", "applications": "#F57C00", "data": "#0F9D58",
    "documents": "#AB47BC", "others": "#9AA0A6", "audit": "#78909C",
}


def semantic_color_map(categories):
    result, fallback_idx = {}, 0
    for cat in categories:
        key = str(cat).strip().lower()
        if key in SEMANTIC_COLORS:
            result[cat] = SEMANTIC_COLORS[key]
        else:
            result[cat] = PALETTE[fallback_idx % len(PALETTE)]
            fallback_idx += 1
    return result


def category_color_map(categories):
    result, fallback_idx = {}, 0
    for cat in categories:
        key = str(cat).strip().lower()
        if key in CATEGORY_COLORS:
            result[cat] = CATEGORY_COLORS[key]
        else:
            result[cat] = PALETTE[fallback_idx % len(PALETTE)]
            fallback_idx += 1
    return result
