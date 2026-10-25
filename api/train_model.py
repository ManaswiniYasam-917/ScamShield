"""Train an optional URL classifier from a CSV with columns url,label (1=phishing/suspicious, 0=benign)."""
import csv, sys, os, joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from ml_detector import features, MODEL_PATH

if len(sys.argv) < 2:
    print('Usage: py train_model.py dataset.csv')
    print('CSV must contain columns: url,label (1=suspicious, 0=benign). Use a lawful, reputable labelled dataset.')
    raise SystemExit(2)
urls, labels = [], []
with open(sys.argv[1], newline='', encoding='utf-8-sig') as f:
    reader = csv.DictReader(f)
    if not {"url", "label"}.issubset(reader.fieldnames or []): raise SystemExit("CSV must have url,label columns")
    for row in reader:
        try:
            label = int(row["label"])
            if label not in (0,1) or not row["url"].strip(): continue
            urls.append(row["url"].strip()); labels.append(label)
        except (ValueError, TypeError): continue
if len(urls) < 20 or len(set(labels)) < 2: raise SystemExit("Need at least 20 valid rows and both labels (0 and 1).")
X = [features(u)[0] for u in urls]
X_train, X_test, y_train, y_test = train_test_split(X, labels, test_size=0.2, random_state=42, stratify=labels)
model = RandomForestClassifier(n_estimators=250, class_weight="balanced", random_state=42)
model.fit(X_train, y_train)
pred = model.predict(X_test)
print("Held-out accuracy:", round(accuracy_score(y_test, pred), 4))
print(classification_report(y_test, pred, zero_division=0))
joblib.dump(model, MODEL_PATH)
print("Saved model to", MODEL_PATH)
print("This evaluation is only as representative as your dataset; do not present it as universal accuracy.")
