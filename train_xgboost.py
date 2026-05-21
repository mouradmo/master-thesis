#!/usr/bin/env python3

import pandas as pd
from sklearn.metrics import classification_report
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
)

model.fit(X_train, y_train)

pred = model.predict(X_test)

print(classification_report(y_test, pred))