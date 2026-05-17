#!/usr/bin/env python3

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from xgboost import XGBClassifier

# Load dataset
df = pd.read_csv("merged_dataset.csv")

# Numeric ML features
features = [
    "duration",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "orig_ip_bytes",
    "resp_pkts",
    "resp_ip_bytes",
    "missed_bytes",
    "ip_proto",
]

# Replace NaN with 0
X = df[features].fillna(0)

# Labels
y = (df["label"] != "benign").astype(int)

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.3,
    random_state=42,
    stratify=y,
)

# Train model
model = XGBClassifier(
    n_estimators=100,
    max_depth=4,
    learning_rate=0.1,
    eval_metric="logloss",
)

model.fit(X_train, y_train)

# Predict
pred = model.predict(X_test)

# Results
print(classification_report(y_test, pred))