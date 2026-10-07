import time
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier

df = pd.read_csv("features_combined.csv")
FEATURES = ['url_length', 'host_length', 'path_length', 'n_hyphens', 'n_dots',
            'n_digits', 'n_slashes', 'n_subdomains', 'has_ip', 'has_at',
            'has_port', 'suspicious_words', 'digit_ratio', 'suspicious_tlds',
            'companies_in_sub', 'tld_length']

# Same preparation as baseline.py, so the test set is identical
data = df.dropna(subset=FEATURES).sample(200000, random_state=42)
X, y = data[FEATURES], data["label"]
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42)

from sklearn.metrics import average_precision_score

ratio = (y_train == 0).sum() / (y_train == 1).sum()

models = {
    "Decision tree (baseline)": DecisionTreeClassifier(max_depth=10, random_state=42),
    "Random forest": RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42),
    "Random forest (balanced)": RandomForestClassifier(n_estimators=100, n_jobs=-1,
                                                       class_weight="balanced", random_state=42),
    "XGBoost (unweighted)": XGBClassifier(n_estimators=300, max_depth=6,
                                          learning_rate=0.1, random_state=42),
    "XGBoost (weighted)": XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1,
                                        scale_pos_weight=ratio, random_state=42),
    "LightGBM (unweighted)": LGBMClassifier(n_estimators=300, learning_rate=0.1,
                                            random_state=42, verbose=-1),
    "LightGBM (weighted)": LGBMClassifier(n_estimators=300, learning_rate=0.1,
                                          scale_pos_weight=ratio, random_state=42, verbose=-1),
}

rows = []
for name, model in models.items():
    start = time.time()
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    score = model.predict_proba(X_test)[:, 1]      # phishing probability per URL
    rows.append({
        "model": name,
        "precision": precision_score(y_test, pred),
        "recall": recall_score(y_test, pred),
        "f1": f1_score(y_test, pred),
        "pr_auc": average_precision_score(y_test, score),
        "train_seconds": time.time() - start,
    })

print(pd.DataFrame(rows).round(3).to_string(index=False))
