import pandas as pd
from sklearn.model_selection import train_test_split #split the data into test and train
from sklearn.tree import DecisionTreeClassifier # flowchart of yes/no questions
from sklearn.ensemble import RandomForestClassifier #classified task
from sklearn.metrics import classification_report #print the score

# Load the combined feature table
df = pd.read_csv("features_combined.csv")

# 16 clues for learning
FEATURES = ['url_length', 'host_length', 'path_length', 'n_hyphens', 'n_dots',
            'n_digits', 'n_slashes', 'n_subdomains', 'has_ip', 'has_at',
            'has_port', 'suspicious_words', 'digit_ratio', 'suspicious_tlds',
            'companies_in_sub', 'tld_length']

def run(data, name):
    #train 2 model on data and print the result
    data = data.dropna(subset=FEATURES) #drop any blank rows that doesnt have the clues
    if len(data) > 200000:                       #use this amount to run/ cuz the data is too big
        data = data.sample(200000, random_state=42) #42 fixed shuffles

    X = data[FEATURES]                           # the clues
    y = data["label"]                            # the answer (1 = phishing)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42)  #20% is for testing

    models = {
        "Decision tree": DecisionTreeClassifier(max_depth=10, random_state=42), # 10 limits the tree to memorize the learning pattern
        "Random forest": RandomForestClassifier(n_estimators=100, n_jobs=-1,
                                                random_state=42)
    }
    for model_name, model in models.items(): #loop thru the dictionary once in each model
        model.fit(X_train, y_train)              # learn from the training part
        pred = model.predict(X_test)             # guess answers for the exam part
        print(f"\n=== {name} | {model_name} ===")
        print(classification_report(y_test, pred, digits=3))

run(df, "A: all sources")
run(df[df["source"] == "iscx"], "B: ISCX only")