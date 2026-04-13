import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler

train_df = pd.read_csv("Monday-WorkingHours.pcap_ISCX.csv")
test_df = pd.read_csv("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")

train_df.columns = train_df.columns.str.strip()
test_df.columns = test_df.columns.str.strip()
 
print("=== train columns ===")
print(train_df.columns.tolist())
print("\n=== test columns ===")
print(test_df.columns.tolist())

# 사용할 feature 선택
features = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Packet Length Mean",
    "Packet Length Std",
    "Flow Packets/s",
    "Flow Bytes/s"
]
X_train = train_df[features].copy()
X_test = test_df[features].copy()

y_train = train_df["Label"].copy()
y_test = test_df["Label"].copy()

X_train.replace([np.inf, -np.inf], np.nan, inplace=True)
X_test.replace([np.inf, -np.inf], np.nan, inplace=True)

for col in features:
    X_train[col] = pd.to_numeric(X_train[col], errors="coerce")
    X_test[col] = pd.to_numeric(X_test[col], errors="coerce")

train_mask = X_train.notna().all(axis=1)
test_mask = X_test.notna().all(axis=1)

X_train = X_train[train_mask].reset_index(drop=True)
X_test = X_test[test_mask].reset_index(drop=True)
y_train = y_train[train_mask].reset_index(drop=True)
y_test = y_test[test_mask].reset_index(drop=True)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

X_train_scaled_df = pd.DataFrame(X_train_scaled, columns=features)
X_test_scaled_df = pd.DataFrame(X_test_scaled, columns=features)

train_processed = X_train_scaled_df.copy()
train_processed["Label"] = y_train

test_processed = X_test_scaled_df.copy()
test_processed["Label"] = y_test


train_processed.to_csv("train_preprocessed.csv", index=False)
test_processed.to_csv("test_preprocessed.csv", index=False)


print("\n전처리 완료")
print("train_processed shape:", train_processed.shape)
print("test_processed shape:", test_processed.shape)

print("\ntrain label counts:")
print(train_processed["Label"].value_counts())

print("\ntest label counts:")
print(test_processed["Label"].value_counts())