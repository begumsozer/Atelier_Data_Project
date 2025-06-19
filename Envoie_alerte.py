

#!/usr/bin/env python3
# send_alerts_to_selim.py
# ------------------------------------------------------------
# 1) Lit le tableau CVE enrichi
# 2) Filtre les vulnérabilités critiques (CVSS ≥ 9  OU  EPSS ≥ 0.7)
# 3) Formate le message e-mail
# 4) Envoie à Mail
# ------------------------------------------------------------
import os
import ssl
import smtplib
import pandas as pd
from email.mime.text import MIMEText
from datetime import datetime

# ------------------------------------------------------------------
# 1) Charger le CSV (chemin local ou absolu)
# ------------------------------------------------------------------
CSV_PATH = "cve_table_finale.csv"          # adaptez si besoin
df = pd.read_csv(CSV_PATH)

# ------------------------------------------------------------------
# 2) Critère d’alerte : CVSS ≥ 9  OU  EPSS ≥ 0.7
# ------------------------------------------------------------------
df["EPSS Score"] = pd.to_numeric(df["EPSS Score"], errors="coerce")
crit = df[(df["CVSS Score"] >= 9) | (df["EPSS Score"] >= 0.7)]

if crit.empty:
    print("✅ Aucun CVE critique à signaler.")
    exit(0)

# ------------------------------------------------------------------
# 3) Construire le corps du mail
# ------------------------------------------------------------------
lines = []
for _, row in crit.iterrows():
    lines.append(
        f"- {row['CVE']} | {row['Éditeur']} {row['Produit']} "
        f"{row['Versions affectées']} | CVSS={row['CVSS Score']} "
        f"EPSS={row['EPSS Score']:.2f}"
    )

body = "\n".join(lines)
subject = f"[ALERTE CVE] {len(crit)} vulnérabilité(s) critique(s) — {datetime.utcnow():%Y-%m-%d}"

# ------------------------------------------------------------------
# 4) Paramètres SMTP (variables d’environnement)
# ------------------------------------------------------------------
SMTP_HOST   = os.getenv("ALERT_SMTP_HOST", "smtp.gmail.com")
SMTP_PORT   = int(os.getenv("ALERT_SMTP_PORT", 465))
FROM_ADDR   = os.getenv("ALERT_MAIL_FROM")      # ex. bot@domaine.com
FROM_PWD    = os.getenv("ALERT_MAIL_PWD")       # app-password ou token OAuth
TO_ADDR     = "Remplir ici pour quel mail envoyer"

if not all([FROM_ADDR, FROM_PWD]):
    raise EnvironmentError("ALERT_MAIL_FROM / ALERT_MAIL_PWD non définis.")

# ------------------------------------------------------------------
# 5) Envoi sécurisé
# ------------------------------------------------------------------
msg = MIMEText(body, "plain", "utf-8")
msg["From"]    = FROM_ADDR
msg["To"]      = TO_ADDR
msg["Subject"] = subject

context = ssl.create_default_context()
with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context) as server:
    server.login(FROM_ADDR, FROM_PWD)
    server.send_message(msg)

print(f"📧  Mail envoyé à {TO_ADDR} ({len(crit)} CVE).")
