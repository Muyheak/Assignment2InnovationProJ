# Assignment2 Innovation Project
## Section 1. Environment SetUp 

## Section 2. Data Processing 

The phishing detector uses three datasets, download and place them in the same folder as the notebook
- 'malicious_phish.csv' - Base dataset
- 'PhishTank_2026.csv' - PhishTank list of reported phishing domains 
- 'top-1m.csv' - Tranco domain lists of legitimate websites 

2.2 Run the the data processing notebook 
Open the notebook, and run every cell from top to bottom 

The notebook will perform four things:
- Cleaning : It drops all of the missing and duplicated URLs which reduces the base dataset from 651,191 to 641,119 rows. 
- Reconcilation: It changes all of the schemas of all three datasets so they all share one common schema (url, label, type, source), furthermore Tranco will be downsized to only 100,000 rows to prevent source dominance, it also concatenates the three sources and also removes the duplicate URLs across the data sets. 
- Normalization: It normalize each URL so they all have the same structure by decoding percent-encoding, lowercasing the scheme, and also adds a default scheme if it is missing 
-Feature extraction: it applies the extract_features(url) function to all of the rows, which produces 16 numeric features that is used for modelling 

The notebook defines phishing as 1, and the other labels (benign, malware, defacement) as 0.

# Model training
1. Environment setup
