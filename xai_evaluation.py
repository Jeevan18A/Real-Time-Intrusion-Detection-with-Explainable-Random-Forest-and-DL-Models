# This file implements explainability evaluation metrics and adversarial robustness testing for the IDS model.

import numpy as np
from lime.lime_tabular import LimeTabularExplainer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import copy

# Dummy data and model for demonstration
np.random.seed(42)
X_train = np.random.rand(100, 10)
y_train = np.random.choice([0, 1], 100)
X_test = np.random.rand(20, 10)
y_test = np.random.choice([0, 1], 20)

# Train a simple classifier
clf = RandomForestClassifier(n_estimators=10, random_state=42)
clf.fit(X_train, y_train)

# Create LIME explainer
explainer = LimeTabularExplainer(X_train, feature_names=[f'feat_{i}' for i in range(10)],
                                 class_names=['class_0', 'class_1'], discretize_continuous=True)

def fidelity(instance, explainer, model):
    """Measure fidelity: how well explanation approximates model locally."""
    exp = explainer.explain_instance(instance, model.predict_proba, num_features=5)
    local_pred = exp.local_pred
    model_pred = model.predict_proba(instance.reshape(1, -1))[0, 1]
    return 1 - abs(local_pred - model_pred)

def stability(instance, explainer, model, noise_level=0.01, n_samples=5):
    """Measure stability: similarity of explanations for similar instances."""
    base_exp = explainer.explain_instance(instance, model.predict_proba, num_features=5)
    base_weights = dict(base_exp.as_list())
    similarities = []
    for _ in range(n_samples):
        noisy_instance = instance + np.random.normal(0, noise_level, size=instance.shape)
        noisy_exp = explainer.explain_instance(noisy_instance, model.predict_proba, num_features=5)
        noisy_weights = dict(noisy_exp.as_list())
        # Compute similarity as cosine similarity of weights vectors
        keys = set(base_weights.keys()).union(noisy_weights.keys())
        base_vec = np.array([base_weights.get(k, 0) for k in keys])
        noisy_vec = np.array([noisy_weights.get(k, 0) for k in keys])
        if np.linalg.norm(base_vec) == 0 or np.linalg.norm(noisy_vec) == 0:
            sim = 0
        else:
            sim = np.dot(base_vec, noisy_vec) / (np.linalg.norm(base_vec) * np.linalg.norm(noisy_vec))
        similarities.append(sim)
    return np.mean(similarities)

def adversarial_robustness(model, X_test, y_test, epsilon=0.1):
    """Simple adversarial robustness test by adding noise and checking accuracy drop."""
    X_adv = X_test + np.random.uniform(-epsilon, epsilon, X_test.shape)
    y_pred_clean = model.predict(X_test)
    y_pred_adv = model.predict(X_adv)
    acc_clean = accuracy_score(y_test, y_pred_clean)
    acc_adv = accuracy_score(y_test, y_pred_adv)
    return acc_clean, acc_adv

if __name__ == "__main__":
    instance = X_test[0]
    print("Fidelity:", fidelity(instance, explainer, clf))
    print("Stability:", stability(instance, explainer, clf))
    acc_clean, acc_adv = adversarial_robustness(clf, X_test, y_test)