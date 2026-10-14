import numpy as np # use to pick random rows 
import pandas as pd
from sklearn.preprocessing import StandardScaler #put the feature in the same scale
from sklearn.cluster import KMeans #clustering model
from sklearn.metrics import silhouette_score # measure how seperated the piles are

FEATURES = ['url_length', 'host_length', 'path_length', 'n_hyphens', 'n_dots',
            'n_digits', 'n_slashes', 'n_subdomains', 'has_ip', 'has_at',
            'has_port', 'suspicious_words', 'digit_ratio', 'suspicious_tlds',
            'companies_in_sub', 'tld_length']
K = 4  #the number of piles 

df = pd.read_csv("features_combined.csv").dropna(subset=FEATURES) #drop any rows that doesn't contain the clues
phish = df[df["label"] == 1].copy()          # keep only phishing rows .copy() create seperate table so adding cloumns doesn't cause warning
X = StandardScaler().fit_transform(phish[FEATURES])   # scale the feature so it fit the average of 0 and typical spread of 1

# Step 1: try several cluster counts (silhouette on a 20k sample to keep it fast)
idx = np.random.RandomState(42).choice(len(X), 20000, replace=False)
for k in range(2, 9):
    km = KMeans(n_clusters=k, n_init=5, random_state=42).fit(X)
    sil = silhouette_score(X[idx], km.labels_[idx])
    print(f"k={k}  inertia={km.inertia_:.0f}  silhouette={sil:.3f}")

# Step 2: cluster with the chosen K and describe each cluster
phish["cluster"] = KMeans(n_clusters=K, n_init=10, random_state=42).fit_predict(X)
overall = phish[FEATURES].mean() # the average of each features across all phishing URLs
profile = phish.groupby("cluster")[FEATURES].mean() # the average in each pile
diff = (profile - overall) / phish[FEATURES].std()   # how far each pile average sits from the overall average measured in standard dev

pd.set_option("display.max_colwidth", 90)
print("\nCluster means:\n", profile.round(2).T)
for c in range(K):
    top = diff.loc[c].abs().sort_values(ascending=False).head(3).index #for each file pick the 3 features with the biggest difference
    print(f"\n=== Cluster {c}: {(phish.cluster == c).sum()} URLs ===")
    for f in top:
        print(f"  {f}: cluster {profile.loc[c, f]:.2f} vs overall {overall[f]:.2f}") #print the 3 feature 
    print(phish[phish.cluster == c]["url"].sample(8, random_state=1).to_string()) # and 8 random example

# Composition checks
print("\nSource composition:\n", pd.crosstab(phish.cluster, phish.source))
print("\nType composition:\n", pd.crosstab(phish.cluster, phish.type))