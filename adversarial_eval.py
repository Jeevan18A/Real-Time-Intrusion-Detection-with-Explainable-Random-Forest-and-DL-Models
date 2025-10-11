import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import accuracy_score, classification_report

# ===============================
# 1. Load model & preprocessing
# ===============================
model = joblib.load("models/model.pkl")
scaler = joblib.load("models/scaler.pkl")

# ===============================
# 2. Load test dataset
# ===============================
data = pd.read_csv("dataset/test.csv")   # must contain a 'label' column
X = data.drop("label", axis=1).values
y = data["label"].values

# Scale with same preprocessing as training
X_scaled = scaler.transform(X)

# ===============================
# 3. Evaluate on clean data
# ===============================
y_pred_clean = model.predict(X_scaled)
acc_clean = accuracy_score(y, y_pred_clean)
print("Clean Data Accuracy:", acc_clean)
print("Clean Classification Report:\n", classification_report(y, y_pred_clean))

# ===============================
# 4. Create Adversarial Variants
# ===============================

# (a) Gaussian noise attack
noise = np.random.normal(0, 0.05, X_scaled.shape)  # mean=0, std=0.05
X_noisy = X_scaled + noise

# (b) Feature flip attack (simulate packet manipulation)
X_flip = X_scaled.copy()
n_samples, n_features = X_flip.shape
flip_fraction = 0.05  # 5% of values flipped
n_flip = int(flip_fraction * n_samples * n_features)

rows = np.random.randint(0, n_samples, n_flip)
cols = np.random.randint(0, n_features, n_flip)
X_flip[rows, cols] = X_flip[rows, cols] * -1  # flip sign

# ===============================
# 5. Evaluate Adversarial Impact
# ===============================
# Noisy data
y_pred_noisy = model.predict(X_noisy)
acc_noisy = accuracy_score(y, y_pred_noisy)

# Flipped data
y_pred_flip = model.predict(X_flip)
acc_flip = accuracy_score(y, y_pred_flip)

print("\nAdversarial Evaluation:")
print(f"Clean Accuracy     : {acc_clean:.4f}")
print(f"Noisy Accuracy     : {acc_noisy:.4f}")
print(f"Feature Flip Acc.  : {acc_flip:.4f}")

# ===============================
# 6. Save results
# ===============================
results = pd.DataFrame({
    "Scenario": ["Clean", "Noisy (Gaussian)", "Feature Flip"],
    "Accuracy": [acc_clean, acc_noisy, acc_flip]
})
results.to_csv("adversarial_results.csv", index=False)
print("\nResults saved to adversarial_results.csv")
