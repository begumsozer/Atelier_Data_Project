#etape 5

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Charger les données
df = pd.read_csv("cve_table_finale.csv")

# Aperçu rapide
df.info()
df.head()

# Filtrer les lignes avec CVSS et EPSS valides
df_cvss = df[df["CVSS Score"].notnull()]
df_epss = df[df["EPSS Score"].notnull()]
df_cvss_epss = df_cvss[df_cvss["EPSS Score"].notnull()]

# Pour les colonnes texte : remplacer les NaN par "Non spécifié"
df["Éditeur"].fillna("Non spécifié", inplace=True)
df["Produit"].fillna("Non spécifié", inplace=True)
df["CWE Description"].fillna("Non spécifié", inplace=True)
df["Versions affectées"].fillna("Non spécifié", inplace=True)

plt.figure(figsize=(8, 5))
plt.hist(df_cvss["CVSS Score"], bins=10, color='skyblue', edgecolor='black')
plt.title("Distribution des scores CVSS")
plt.xlabel("Score CVSS")
plt.ylabel("Nombre de vulnérabilités")
plt.grid(True)
plt.show()

plt.figure(figsize=(6, 6))
df["Base Severity"].value_counts().plot.pie(autopct='%1.1f%%', startangle=90, colors=sns.color_palette("pastel"))
plt.title("Répartition des vulnérabilités par gravité")
plt.ylabel("")
plt.show()

plt.figure(figsize=(8, 5))
plt.scatter(df_cvss_epss["CVSS Score"], df_cvss_epss["EPSS Score"], alpha=0.6, color='orange')
plt.title("CVSS vs EPSS")
plt.xlabel("Score CVSS")
plt.ylabel("Score EPSS")
plt.grid(True)
plt.show()

plt.figure(figsize=(10, 5))
df["Éditeur"].value_counts().head(10).plot(kind="bar", color="salmon")
plt.title("Top 10 des éditeurs les plus affectés")
plt.ylabel("Nombre de vulnérabilités")
plt.xticks(rotation=45)
plt.grid(axis='y')
plt.show()

top_editeurs = df["Éditeur"].value_counts().head(5).index
df_top = df[df["Éditeur"].isin(top_editeurs) & df["CVSS Score"].notnull()]

plt.figure(figsize=(10, 5))
sns.boxplot(data=df_top, x="Éditeur", y="CVSS Score")
plt.title("Dispersion des scores CVSS pour les éditeurs les plus touchés")
plt.grid(True)
plt.show()

import numpy as np

# Créer un DataFrame avec uniquement les colonnes numériques pertinentes
df_corr = df[["CVSS Score", "EPSS Score"]].dropna()

# Calcul de la corrélation
correlation_matrix = df_corr.corr()

# Affichage en heatmap
plt.figure(figsize=(6, 4))
sns.heatmap(correlation_matrix, annot=True, cmap="coolwarm", fmt=".2f")
plt.title("Corrélation entre CVSS Score et EPSS Score")
plt.show()
