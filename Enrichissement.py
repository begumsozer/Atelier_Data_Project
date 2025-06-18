# -----------------------------------------------------------
# 6) Interroger les API MITRE CVE AWG + EPSS pour chaque CVE
# -----------------------------------------------------------
import requests, json, time
import pandas as pd
from pathlib import Path

# 1) Lire la liste des CVE collectés à l’étape 5
with open("cve_ids.txt", encoding="utf-8") as f:
    cve_list = [ln.strip() for ln in f if ln.strip()]


cve_list = cve_list[:500]          # ← limite aux 1 000 premiers identifiants

print(f"🔍  Interrogation de {len(cve_list)} identifiants CVE")

# 2) Préparer une structure pour stocker tous les résultats
records = []

# 3) Boucle principale — le code interne est VOTRE exemple inchangé
for cve_id in cve_list:
    try:
        # ================= MITRE CVE AWG =================
        url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        response = requests.get(url, timeout=15)
        data = response.json()           # <-- peut lever ValueError si pas du JSON

        # Extraire la description
        description = data["containers"]["cna"]["descriptions"][0]["value"]

        # Extraire le score CVSS (prise en compte de toutes les variantes)
        cvss_score = ""
        try:
            cvss_score = data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"]
        except KeyError:
            try:
                cvss_score = data["containers"]["cna"]["metrics"][0]["cvssV3_0"]["baseScore"]
            except KeyError:
                pass                        # le champ n’existe pas → reste vide

        # Extraire le CWE
        cwe       = "Non disponible"
        cwe_desc  = "Non disponible"
        problemtype = data["containers"]["cna"].get("problemTypes", [])
        if problemtype and problemtype[0].get("descriptions"):
            cwe       = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
            cwe_desc  = problemtype[0]["descriptions"][0].get("description", "Non disponible")

        # Extraire les produits affectés
        affected_str = ""
        affected = data["containers"]["cna"].get("affected", [])
        if affected:
            lines = []
            for product in affected:
                vendor        = product.get("vendor", "Inconnu")
                product_name  = product.get("product", "Inconnu")
                versions = [
                    v["version"]
                    for v in product.get("versions", [])
                    if v.get("status") == "affected"
                ]
                lines.append(f"{vendor} | {product_name} | {', '.join(versions)}")
            affected_str = " || ".join(lines)

        # ================ EPSS ============================
        epss_score = ""
        try:
            url_epss = f"https://api.first.org/data/v1/epss?cve={cve_id}"
            epss_resp = requests.get(url_epss, timeout=10)
            epss_json = epss_resp.json()
            epss_data = epss_json.get("data", [])
            if epss_data:
                epss_score = epss_data[0]["epss"]
        except Exception:
            pass  # on ignore les échecs EPSS

        # Affichage (conserve exactement vos prints)
        print(f"\nCVE : {cve_id}")
        print(f"Description : {description}")
        print(f"Score CVSS : {cvss_score}")
        print(f"Type CWE : {cwe}")
        print(f"CWE Description : {cwe_desc}")
        print(f"Score EPSS : {epss_score}")
        if affected_str:
            print(f"Produits affectés : {affected_str}")

        # Mémoriser dans la table finale
        records.append(
            {
                "cve":            cve_id,
                "description":    description,
                "cvss_score":     cvss_score,
                "cwe":            cwe,
                "cwe_description": cwe_desc,
                "epss_score":     epss_score,
                "affected":       affected_str,
            }
        )

        time.sleep(0.001)  # petite pause pour ne pas surcharger les API

    except Exception as e:
        print(f"\n⚠️  Problème avec {cve_id} → {e}")

# 4) Exporter la récolte dans un CSV
out_df = pd.DataFrame(records)
out_df.to_csv("cve_enrichissement_api.csv", index=False, encoding="utf-8")
print(f"\n  Fichier 'cve_enrichissement_api.csv' écrit ({len(out_df)} lignes)")
