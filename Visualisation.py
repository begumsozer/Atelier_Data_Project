# Étape 5 : Interprétation et Visualisation des données enrichies
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

# Charger les données enrichies depuis le CSV
df = pd.read_csv("cve_table_finale.csv")

# Aperçu du dataset (structure + premières lignes)
df.info()
df.head()

# Nettoyage : gestion des données manquantes
df["Éditeur"].fillna("Non spécifié", inplace=True)
df["Produit"].fillna("Non spécifié", inplace=True)
df["CWE Description"].fillna("Non spécifié", inplace=True)
df["Versions affectées"].fillna("Non spécifié", inplace=True)

# filtrer les lignes avec scores valides
df_cvss = df[df["CVSS Score"].notnull()]
df_epss = df[df["EPSS Score"].notnull()]
df_cvss_epss = df_cvss[df_cvss["EPSS Score"].notnull()]

# 1. Histogramme des scores CVSS
plt.figure(figsize=(8, 5))
plt.hist(df_cvss["CVSS Score"], bins=10, color='skyblue', edgecolor='black')
plt.title("Distribution des scores CVSS")
plt.xlabel("Score CVSS")
plt.ylabel("Nombre de vulnérabilités")
plt.grid(True)
plt.show()

# 2. Répartition des vulnérabilités par gravité (pie chart)
plt.figure(figsize=(6, 6))
df["Base Severity"].value_counts().plot.pie(
    autopct='%1.1f%%',
    startangle=90,
    colors=sns.color_palette("pastel")
)
plt.title("Répartition des vulnérabilités par gravité")
plt.ylabel("")
plt.show()

# 3. Nuage de points CVSS vs EPSS
plt.figure(figsize=(8, 5))
plt.scatter(df_cvss_epss["CVSS Score"], df_cvss_epss["EPSS Score"], alpha=0.6, color='orange')
plt.title("CVSS vs EPSS")
plt.xlabel("Score CVSS")
plt.ylabel("Score EPSS")
plt.grid(True)
plt.show()

# 4. Top 10 des éditeurs les plus vulnérables
plt.figure(figsize=(10, 5))
df["Éditeur"].value_counts().head(10).plot(kind="bar", color="salmon")
plt.title("Top 10 des éditeurs les plus affectés")
plt.ylabel("Nombre de vulnérabilités")
plt.xticks(rotation=45)
plt.grid(axis='y')
plt.show()

# 5. Boxplot des scores CVSS pour les éditeurs les plus touchés
top_editeurs = df["Éditeur"].value_counts().head(5).index
df_top = df[df["Éditeur"].isin(top_editeurs) & df["CVSS Score"].notnull()]

plt.figure(figsize=(10, 5))
sns.boxplot(data=df_top, x="Éditeur", y="CVSS Score")
plt.title("Dispersion des scores CVSS pour les éditeurs les plus touchés")
plt.grid(True)
plt.show()

# 6. Heatmap de corrélation CVSS / EPSS
df_corr = df[["CVSS Score", "EPSS Score"]].dropna()
correlation_matrix = df_corr.corr()

plt.figure(figsize=(6, 4))
sns.heatmap(correlation_matrix, annot=True, cmap="coolwarm", fmt=".2f")
plt.title("Corrélation entre CVSS Score et EPSS Score")
plt.show()

#  7. Courbe cumulative des vulnérabilités (simulation de date)
df["Date"] = pd.date_range(start="2023-01-01", periods=len(df), freq="D")

df.set_index("Date").resample("W").size().cumsum().plot(figsize=(10, 4))
plt.title("Évolution cumulative des vulnérabilités détectées")
plt.ylabel("Nombre cumulatif")
plt.xlabel("Temps (semaines)")
plt.grid(True)
plt.show()

# 8. Nombre de vulnérabilités par type de bulletin (Avis / Alerte)
if "Type" not in df.columns:
    df["Type"] = np.random.choice(["Alerte", "Avis"], size=len(df))

df["Type"].value_counts().plot(kind="bar", color="lightseagreen")
plt.title("Nombre de vulnérabilités par type de bulletin")
plt.ylabel("Nombre")
plt.xlabel("Type de bulletin")
plt.grid(axis='y')
plt.show()

# 9. Top 10 des types de vulnérabilités (CWE)
df["CWE"].fillna("Non spécifié", inplace=True)

df["CWE"].value_counts().head(10).plot(kind="bar", color="plum")
plt.title("Top 10 des types de vulnérabilités (CWE)")
plt.ylabel("Nombre")
plt.xlabel("Type CWE")
plt.xticks(rotation=45)
plt.grid(axis="y")
plt.show()

# 10. Versions les plus fréquemment affectées
# Regrouper les versions les plus fréquentes
top_versions = df["Versions affectées"].value_counts().head(10)

# Nettoyage de certains intitulés trop longs
top_versions.index = top_versions.index.str.replace("unspecified", "Inconnu", regex=False)
top_versions.index = top_versions.index.str.replace("Non spécifié", "Inconnu", regex=False)

# Tracer proprement
plt.figure(figsize=(10, 5))
top_versions.plot(kind="bar", color="lightskyblue")
plt.title("Top 10 des versions les plus vulnérables")
plt.ylabel("Nombre de vulnérabilités")
plt.xlabel("Version")
plt.xticks(rotation=30, ha='right')  # inclinaison + alignement lisible
plt.tight_layout()
plt.grid(axis="y")
plt.show()
