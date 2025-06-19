# 🛡️ Analyse automatisée des avis & alertes ANSSI  
**Mastercamp EFREI 2025**

Ce projet orchestre l’intégralité du cycle de vie d’une vulnérabilité :

1. **Collecte** des bulletins ANSSI (flux RSS).  
2. **Extraction & enrichissement** des identifiants CVE (CVSS MITRE, EPSS, CWE…).  
3. **Analyses visuelles** + **modèles ML** (PCA + K-Means, Random Forest).  
4. **Génération d’alertes e-mail** personnalisées pour chaque abonné.

---

## 1. Prérequis

| Outil | Version conseillée |
|-------|-------------------|
| Python | ≥ 3.10 |
| `pip` / `venv` | Isolation d’environnement |
| JupyterLab *(optionnel)* | Exécution interactive des notebooks |
| Compte SMTP | Gmail (App-Password/OAuth) ou serveur d’entreprise |

---

## 2. Exécution du notebook pas à pas

| Étape | Commande (terminal) | Ce qu’il se passe |
|-------|---------------------|-------------------|
| **a. Lancer JupyterLab** | ```bash<br>jupyter lab<br>``` | Ouvre l’interface web Jupyter dans votre navigateur. |
| **b. Ouvrir le notebook** | Naviguez dans l’explorateur Jupyter jusqu’à **`notebooks/Visualisations_ML.ipynb`** et cliquez dessus. | Le notebook se charge, prêt à être exécuté. |
| **c. Exécuter toutes les cellules** | Dans Jupyter : *Run ▸ Run All Cells* (ou **Maj + Entrée** cellule par cellule). | 1. Charge `cve_table_finale.csv`.<br>2. Affiche les graphiques (histogramme CVSS, heatmap…).<br>3. Lance PCA + K-Means.<br>4. Entraîne le Random Forest et affiche la matrice de confusion. |

---
