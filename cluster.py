import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score

FEATURES = ['url_length', 'host_length', 'path_length', 'n_hyphens', 'n_dots',
            'n_digits', 'n_slashes', 'n_subdomains', 'has_ip', 'has_at',
            'has_port', 'suspicious_words', 'digit_ratio', 'suspicious_tlds',
            'companies_in_sub', 'tld_length']
K = 4   # change this after reading the table printed below

df = pd.read_csv("features_combined.csv").dropna(subset=FEATURES)
phish = df[df["label"] == 1].copy()          # one class only; labels are not used below
X = StandardScaler().fit_transform(phish[FEATURES])   # put features on one scale

# Step 1: try several cluster counts (silhouette on a 20k sample to keep it fast)
idx = np.random.RandomState(42).choice(len(X), 20000, replace=False)
for k in range(2, 9):
    km = KMeans(n_clusters=k, n_init=5, random_state=42).fit(X)
    sil = silhouette_score(X[idx], km.labels_[idx])
    print(f"k={k}  inertia={km.inertia_:.0f}  silhouette={sil:.3f}")

# Step 2: cluster with the chosen K and describe each cluster
phish["cluster"] = KMeans(n_clusters=K, n_init=10, random_state=42).fit_predict(X)
overall = phish[FEATURES].mean()
profile = phish.groupby("cluster")[FEATURES].mean()
diff = (profile - overall) / phish[FEATURES].std()   # difference in standard deviations

pd.set_option("display.max_colwidth", 90)
print("\nCluster means:\n", profile.round(2).T)
for c in range(K):
    top = diff.loc[c].abs().sort_values(ascending=False).head(3).index
    print(f"\n=== Cluster {c}: {(phish.cluster == c).sum()} URLs ===")
    for f in top:
        print(f"  {f}: cluster {profile.loc[c, f]:.2f} vs overall {overall[f]:.2f}")
    print(phish[phish.cluster == c]["url"].sample(8, random_state=1).to_string())

# Composition checks
print("\nSource composition:\n", pd.crosstab(phish.cluster, phish.source))
print("\nType composition:\n", pd.crosstab(phish.cluster, phish.type))