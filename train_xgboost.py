#!/usr/bin/env python3

import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from xgboost import XGBClassifier

train_df = pd.read_csv("train_dataset.csv")
test_df = pd.read_csv("test_dataset.csv")

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

X_train = train_df[features].fillna(0)
y_train = (train_df["label"] != "benign").astype(int)

X_test = test_df[features].fillna(0)
y_test = (test_df["label"] != "benign").astype(int)

model = XGBClassifier(
    n_estimators=100,
    max_depth=4,
    learning_rate=0.1,
    eval_metric="logloss",
    random_state=42,
)

model.fit(X_train, y_train)

pred = model.predict(X_test)

tn, fp, fn, tp = confusion_matrix(y_test, pred, labels=[0, 1]).ravel()

accuracy = accuracy_score(y_test, pred)
precision = precision_score(y_test, pred, zero_division=0)
recall = recall_score(y_test, pred, zero_division=0)
f1 = f1_score(y_test, pred, zero_division=0)

print("\nExperiment results")
print("------------------")
print(f"TP: {tp}")
print(f"TN: {tn}")
print(f"FP: {fp}")
print(f"FN: {fn}")
print()
print(f"Accuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1-score : {f1:.4f}")