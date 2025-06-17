# -----------------------------------------------------------
# 1) Imports + where the raw files live
# -----------------------------------------------------------
from pathlib import Path
import json, re, html
import pandas as pd
from json import JSONDecodeError

ALERTE_DIR = Path(r"data_pour_TD_final\alertes")
AVIS_DIR = Path(r"data_pour_TD_final\Avis")


# -----------------------------------------------------------
# 2) Helpers
# -----------------------------------------------------------
def strip_md(text: str | None) -> str:
    """Drop HTML/Markdown – keep plain text."""
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", "", text)        # HTML tags
    text = re.sub(r"[*_`#>-]", "", text)       # basic MD chars
    return html.unescape(text).strip()


def read_json(path: Path) -> dict | None:
    """Try UTF-8 first, then cp1252; return None if not JSON."""
    for enc in ("utf-8", "cp1252"):
        try:
            return json.loads(path.read_text(encoding=enc))
        except (UnicodeDecodeError, JSONDecodeError):
            continue
    return None


def record_from_obj(obj: dict, kind: str) -> dict:
    """Flatten one CERT-FR object into a flat dict ready for DataFrame."""
    return {
        "reference": obj.get("reference"),
        "title":     obj.get("title"),
        "closed_at": obj.get("closed_at") if kind == "alerte" else "",
        "cves":      "; ".join(c["name"] for c in obj.get("cves", [])) or "Aucune",
        "risks":     "; ".join(r["description"] for r in obj.get("risks", [])) or "Non précisé",
        "summary":   strip_md(obj.get("summary"))[:1500],   # trim long blobs
        "first_revision": (obj.get("revisions") or [{}])[0].get("revision_date", ""),
        "affected_systems": " | ".join(
            f'{s.get("product", {}).get("vendor", {}).get("name","?")} '
            f'{s.get("product", {}).get("name","?")} – {s.get("description","")}'
            for s in obj.get("affected_systems", [])
        ),
    }

# -----------------------------------------------------------
# 3) Walk the folders, parse everything
# -----------------------------------------------------------
def build_df(folder: Path, kind: str) -> pd.DataFrame:
    rows, bad = [], []
    for f in folder.rglob("*"):                 # recurse (works with nested folders)
        if not f.is_file():
            continue
        obj = read_json(f)
        if obj is None:
            bad.append(f.name)
            continue
        rows.append(record_from_obj(obj, kind))
    if bad:
        print(f"⚠️  {len(bad)} files in '{folder.name}' skipped (non-JSON or unreadable)")
    return pd.DataFrame(rows)

alerte_df = build_df(ALERTE_DIR, "alerte")
avis_df   = build_df(AVIS_DIR,   "avis")


# -----------------------------------------------------------
# 4) Write the spreadsheets & preview
# -----------------------------------------------------------
alerte_df.to_csv("alertes.csv", index=False, encoding="utf-8")
avis_df.to_csv("avis.csv",     index=False, encoding="utf-8")

print(f"✅  {len(alerte_df):>4} alertes → alertes.csv")
print(f"✅  {len(avis_df):>4} avis    → avis.csv")

