import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse

# Load raw logs
df = pd.read_csv("../data/honeypot_realistic_1000.csv")

# Feature: number of failed logins (already in CSV)
df['failed_logins'] = df['failed_logins'].fillna(0)

# Feature: count of commands (already in CSV)
df['commands_count'] = df['commands_count'].fillna(0)

# Feature: does the command contain a URL?
df['has_url'] = df['command'].apply(lambda x: int(bool(re.search(r"http[s]?://", str(x)))))

# Feature: is there a payload hash present?
df['payload_hash_present'] = df['payload_hash'].apply(lambda x: int(pd.notnull(x)))

# Feature: latitude and longitude (already in CSV)
df['geo_lat'] = df['geo_lat'].fillna(0)
df['geo_lon'] = df['geo_lon'].fillna(0)

# Feature: threat score (already in CSV)
df['threat_score'] = df['threat_score'].fillna(0)

# Save processed features for ML
df.to_csv("../outputs/processed_features.csv", index=False)

print("Feature extraction complete. Saved to outputs/processed_features.csv")