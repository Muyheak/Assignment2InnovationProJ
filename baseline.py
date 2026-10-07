import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# Load the combined feature table
df = pd.read_csv("features_combined.csv")

# The 16 clue columns the model learns from
FEATURES = ['url_length', 'host_length', 'path_length', 'n_hyphens', 'n_dots',
            'n_digits', 'n_slashes', 'n_subdomains', 'has_ip', 'has_at',
            'has_port', 'suspicious_words', 'digit_ratio', 'suspicious_tlds',
            'companies_in_sub', 'tld_length']

def run(data, name):
    """Train two models on `data` and print how well they do."""
    data = data.dropna(subset=FEATURES)
    if len(data) > 200000:                       # use a sample so it runs fast
        data = data.sample(200000, random_state=42)

    X = data[FEATURES]                           # the clues
    y = data["label"]                            # the answer (1 = phishing)

    # 80% to learn from, 20% held back as the "exam".
    # stratify keeps the phishing share the same in both parts.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42)

    models = {
        "Decision tree": DecisionTreeClassifier(max_depth=10, random_state=42),
        "Random forest": RandomForestClassifier(n_estimators=100, n_jobs=-1,
                                                random_state=42),
    }
    for model_name, model in models.items():
        model.fit(X_train, y_train)              # learn from the training part
        pred = model.predict(X_test)             # guess answers for the exam part
        print(f"\n=== {name} | {model_name} ===")
        print(classification_report(y_test, pred, digits=3))

run(df, "A: all sources")
run(df[df["source"] == "iscx"], "B: ISCX only")