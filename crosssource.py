import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import recall_score

FEATURES = ['url_length', 'host_length', 'path_length', 'n_hyphens', 'n_dots',
            'n_digits', 'n_slashes', 'n_subdomains', 'has_ip', 'has_at',
            'has_port', 'suspicious_words', 'digit_ratio', 'suspicious_tlds',
            'companies_in_sub', 'tld_length']

df = pd.read_csv("features_combined.csv").dropna(subset=FEATURES)

# Hold out 20% of ISCX as a normal same-source test
iscx = df[df["source"] == "iscx"]
iscx_train, iscx_test = train_test_split(
    iscx, test_size=0.2, stratify=iscx["label"], random_state=42)

tranco = df[df["source"] == "tranco"]
phish = df[df["source"] == "phishtank"]    # never seen during training

# Train WITHOUT any PhishTank rows
train = pd.concat([iscx_train, tranco]).sample(200000, random_state=42)
model = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
model.fit(train[FEATURES], train["label"])

# 1) Recall on phishing from a source the model has seen
same = recall_score(iscx_test["label"], model.predict(iscx_test[FEATURES]))
# 2) Recall on phishing from a source it has never seen
new = (model.predict(phish[FEATURES]) == 1).mean()
# 3) False alarm rate on held-out safe ISCX URLs
safe_test = iscx_test[iscx_test["label"] == 0]
fpr = (model.predict(safe_test[FEATURES]) == 1).mean()

print(f"Recall on ISCX phishing (seen source):      {same:.3f}")
print(f"Recall on PhishTank phishing (new source):  {new:.3f}")
print(f"False alarm rate on held-out safe URLs:     {fpr:.3f}")

# ---- Error analysis ----
phish = phish.copy()
phish["pred"] = model.predict(phish[FEATURES])
missed, caught = phish[phish.pred == 0], phish[phish.pred == 1]
print(f"\nMissed: {len(missed)}  Caught: {len(caught)}")

# Average feature values: missed vs caught PhishTank, and ISCX training phishing
compare = pd.DataFrame({
    "missed": missed[FEATURES].mean(),
    "caught": caught[FEATURES].mean(),
    "iscx_phish": iscx_train[iscx_train.label == 1][FEATURES].mean(),
}).round(2)
print(compare)

pd.set_option("display.max_colwidth", 100)
print("\n20 MISSED PhishTank URLs:")
print(missed["url"].sample(20, random_state=1).to_string())
print("\n10 CAUGHT PhishTank URLs:")
print(caught["url"].sample(10, random_state=1).to_string())

# False positives: safe ISCX URLs flagged as phishing
fp = safe_test[model.predict(safe_test[FEATURES]) == 1]
print("\n15 FALSE ALARMS (safe URLs flagged):")
print(fp["url"].sample(min(15, len(fp)), random_state=1).to_string())

# Which registered domains do missed vs caught URLs sit on?
def reg_domain(urls):
    host = urls.str.extract(r"^https?://([^/?#]+)")[0]
    return host.str.split(".").str[-2:].str.join(".")

print("\nTop domains among MISSED:")
print(reg_domain(missed["url"]).value_counts().head(15))
print("\nTop domains among CAUGHT:")
print(reg_domain(caught["url"]).value_counts().head(15))

# What category are the 'false alarms' really?
print("\nCategory of false alarms:")
print(fp["type"].value_counts())
print("\nCategory of ALL held-out safe URLs:")
print(safe_test["type"].value_counts())