import pandas as pd
from pathlib import Path

# -----------------------------------------------------------
# 1) Lecture du fichier CSV
# -----------------------------------------------------------
csv_path = Path("cve_enrichissement_api.csv")  # adaptez si besoin
if not csv_path.exists():
    raise FileNotFoundError(
        f"Le fichier {csv_path} est introuvable. "
        "Vérifiez son nom ou son emplacement."
    )

df_raw = pd.read_csv(csv_path, encoding="utf-8")

# -----------------------------------------------------------
# 2) Nettoyage & typage
# -----------------------------------------------------------
# Score CVSS et EPSS en flottants (parfois vides → erreurs silencieuses)
df_raw["cvss_score"] = pd.to_numeric(df_raw["cvss_score"], errors="coerce")
df_raw["epss_score"] = pd.to_numeric(df_raw["epss_score"], errors="coerce").round(4)

# -----------------------------------------------------------
# 3) Base Severity (selon CVSS v3.x)
# -----------------------------------------------------------
def cvss_to_severity(score: float | None) -> str:
    if pd.isna(score):
        return "Non défini"
    if score < 4.0:
        return "Faible"
    if score < 7.0:
        return "Moyenne"
    if score < 9.0:
        return "Élevée"
    return "Critique"

df_raw["base_severity"] = df_raw["cvss_score"].apply(cvss_to_severity)

# -----------------------------------------------------------
# 4) Décomposition de la colonne 'affected'
# -----------------------------------------------------------
# La chaîne est de la forme «vendor | product | 1.0, 1.1 || …»
def split_affected(row):
    if pd.isna(row):
        return pd.Series({"vendor": None, "product": None, "versions": None})
    # On ne garde que le premier triplet (si plusieurs produits séparés par ' || ')
    first = row.split(" || ")[0]
    parts = [p.strip() for p in first.split("|")]
    # Sécurité : on pad la liste
    parts += [None] * (3 - len(parts))
    vendor, product, versions = parts[:3]
    return pd.Series({"vendor": vendor, "product": product, "versions": versions})

affected_expanded = df_raw["affected"].apply(split_affected)
df = pd.concat([df_raw.drop(columns=["affected"]), affected_expanded], axis=1)

# -----------------------------------------------------------
# 5) Réorganisation des colonnes (ordre + renommage)
# -----------------------------------------------------------
df = df[
    [
        "cve",
        "cvss_score",
        "base_severity",
        "epss_score",
        "cwe",
        "cwe_description",
        "vendor",
        "product",
        "versions",
        "description",
    ]
].rename(
    columns={
        "cve": "CVE",
        "cvss_score": "CVSS Score",
        "base_severity": "Base Severity",
        "epss_score": "EPSS Score",
        "cwe": "CWE",
        "cwe_description": "CWE Description",
        "vendor": "Éditeur",
        "product": "Produit",
        "versions": "Versions affectées",
        "description": "Description",
    }
)

# -----------------------------------------------------------
# 6) Affichage et export
# -----------------------------------------------------------
print("\n↦ Aperçu du tableau (10 premières lignes) :")

# Sauvegarde au besoin
df.to_csv("cve_table_finale.csv", index=False, encoding="utf-8")
df.to_excel("cve_table_finale.xlsx", index=False)
print("\n✅  Fichiers 'cve_table_finale.csv' et 'cve_table_finale.xlsx' créés.")
