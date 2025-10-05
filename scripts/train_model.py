import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# Load processed features
df = pd.read_csv("../outputs/processed_features.csv")

# Define features and target
X = df[['failed_logins', 'commands_count', 'has_url', 'payload_hash_present', 'geo_lat', 'geo_lon', 'threat_score']]
y = df['attack_type'].apply(lambda x: 0 if x == 'benign' else 1)  # 0=benign, 1=malicious

# Split into train and test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train Random Forest
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Evaluate
y_pred = clf.predict(X_test)
print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Save model
joblib.dump(clf, "../models/honeypot_model.pkl")
print("Model trained and saved to models/honeypot_model.pkl")