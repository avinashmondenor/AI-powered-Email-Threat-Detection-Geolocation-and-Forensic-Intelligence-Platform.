import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
from typing import Dict, Any

FEATURE_KEYS = [
    "spf_fail", "dkim_fail", "dmarc_fail", "reply_to_mismatch",
    "vpn_detected", "proxy_detected", "tor_detected", "hosting_ip",
    "new_domain", "lookalike_domain", "suspicious_url", "redirect_detected",
    "urgency_language", "credential_request", "financial_request", "suspicious_attachment"
]

class MLThreatModel:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=50, random_state=42)
        self.is_trained = False
        self.metrics = {}
        self._train_initial_model()

    def _generate_synthetic_dataset(self, n_samples=300):
        np.random.seed(42)
        X = []
        y = []

        for _ in range(n_samples):
            # 50% benign, 50% malicious/phishing
            label = 1 if np.random.rand() > 0.5 else 0

            if label == 1:
                # Malicious profile: high probability of threat features
                row = [
                    np.random.choice([0, 1], p=[0.2, 0.8]), # spf_fail
                    np.random.choice([0, 1], p=[0.3, 0.7]), # dkim_fail
                    np.random.choice([0, 1], p=[0.1, 0.9]), # dmarc_fail
                    np.random.choice([0, 1], p=[0.2, 0.8]), # reply_to_mismatch
                    np.random.choice([0, 1], p=[0.7, 0.3]), # vpn_detected
                    np.random.choice([0, 1], p=[0.7, 0.3]), # proxy_detected
                    np.random.choice([0, 1], p=[0.8, 0.2]), # tor_detected
                    np.random.choice([0, 1], p=[0.4, 0.6]), # hosting_ip
                    np.random.choice([0, 1], p=[0.4, 0.6]), # new_domain
                    np.random.choice([0, 1], p=[0.3, 0.7]), # lookalike_domain
                    np.random.choice([0, 1], p=[0.2, 0.8]), # suspicious_url
                    np.random.choice([0, 1], p=[0.5, 0.5]), # redirect_detected
                    np.random.choice([0, 1], p=[0.3, 0.7]), # urgency_language
                    np.random.choice([0, 1], p=[0.3, 0.7]), # credential_request
                    np.random.choice([0, 1], p=[0.5, 0.5]), # financial_request
                    np.random.choice([0, 1], p=[0.6, 0.4]), # suspicious_attachment
                ]
            else:
                # Benign profile: low probability of threat features
                row = [
                    np.random.choice([0, 1], p=[0.95, 0.05]),
                    np.random.choice([0, 1], p=[0.95, 0.05]),
                    np.random.choice([0, 1], p=[0.98, 0.02]),
                    np.random.choice([0, 1], p=[0.99, 0.01]),
                    np.random.choice([0, 1], p=[0.90, 0.10]),
                    np.random.choice([0, 1], p=[0.95, 0.05]),
                    np.random.choice([0, 1], p=[0.99, 0.01]),
                    np.random.choice([0, 1], p=[0.80, 0.20]),
                    np.random.choice([0, 1], p=[0.95, 0.05]),
                    np.random.choice([0, 1], p=[0.99, 0.01]),
                    np.random.choice([0, 1], p=[0.98, 0.02]),
                    np.random.choice([0, 1], p=[0.95, 0.05]),
                    np.random.choice([0, 1], p=[0.90, 0.10]),
                    np.random.choice([0, 1], p=[0.98, 0.02]),
                    np.random.choice([0, 1], p=[0.95, 0.05]),
                    np.random.choice([0, 1], p=[0.99, 0.01]),
                ]
            X.append(row)
            y.append(label)

        return np.array(X), np.array(y)

    def _train_initial_model(self):
        X, y = self._generate_synthetic_dataset(n_samples=400)
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        self.model.fit(X_train, y_train)
        y_pred = self.model.predict(X_test)

        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        cm = confusion_matrix(y_test, y_pred).tolist()

        importances = dict(zip(FEATURE_KEYS, [round(float(imp), 4) for imp in self.model.feature_importances_]))

        self.metrics = {
            "dataset_samples": len(X),
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "precision": round(float(prec), 3),
            "recall": round(float(rec), 3),
            "f1_score": round(float(f1), 3),
            "confusion_matrix": cm,
            "feature_importances": importances
        }
        self.is_trained = True

    def predict(self, feature_dict: Dict[str, bool]) -> Dict[str, Any]:
        if not self.is_trained:
            self._train_initial_model()

        vector = [1 if feature_dict.get(k, False) else 0 for k in FEATURE_KEYS]
        prob = self.model.predict_proba([vector])[0][1] # Probability of malicious class
        pred = int(self.model.predict([vector])[0])

        return {
            "ml_threat_probability": round(float(prob), 4),
            "ml_prediction": "MALICIOUS" if pred == 1 else "BENIGN",
            "model_type": "RandomForestClassifier",
            "metrics": self.metrics
        }

ml_model_instance = MLThreatModel()
