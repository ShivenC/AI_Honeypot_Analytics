# scripts/dashboard.py
import streamlit as st
import pandas as pd
import plotly.express as px
from sklearn.ensemble import RandomForestClassifier
import numpy as np

# ---- Streamlit Page Setup ----
st.set_page_config(page_title="AI-Powered Honeypot Analytics Dashboard", layout="wide")
st.title("AI-Powered Honeypot Analytics Dashboard")

st.subheader("AI-Generated Report")
if st.button("Generate AI Report (GPT-5)"):
    try:
        # load OpenAI key from Streamlit secrets or environment
        openai_key = None
        if "OPENAI_API_KEY" in st.secrets:
            openai_key = st.secrets["OPENAI_API_KEY"]
@@ -41,10 +41,8 @@
        else:
            openai.api_key = openai_key




# ---- Load Data ----
logs_path = "data/honeypot_realistic_1000.csv"
try:
    df = pd.read_csv(logs_path)
except Exception as e:
    st.error(f"Failed to load data from {logs_path}: {e}")
    st.stop()

# Convert payload_hash to binary feature
df['payload_hash_present'] = df['payload_hash'].notna().astype(int)

# Show number of rows loaded
st.write(f"Number of sessions loaded: {len(df)}")

st.subheader("Raw Honeypot Logs")
st.dataframe(df)

# ---- Summary Charts ----
st.subheader("Attack Type Distribution")
if 'attack_type' in df.columns:
    attack_counts = df['attack_type'].value_counts()
    fig1 = px.bar(x=attack_counts.index, y=attack_counts.values,
                  labels={'x':'Attack Type','y':'Count'},
                  title="Attack Type Distribution")
    st.plotly_chart(fig1, use_container_width=True)

st.subheader("Threat Scores Distribution")
if 'threat_score' in df.columns:
    fig2 = px.histogram(df, x='threat_score', nbins=20, title="Threat Score Histogram")
    st.plotly_chart(fig2, use_container_width=True)

st.subheader("Attacks by Location")
if {'geo_lat','geo_lon'}.issubset(df.columns):
    fig3 = px.scatter_geo(
        df.dropna(subset=['geo_lat','geo_lon']),
        lat='geo_lat', lon='geo_lon',
        color='attack_type',
        size='threat_score',
        hover_name='src_ip',
        title="Global Attack Map"
    )
    st.plotly_chart(fig3, use_container_width=True)

# ---- Real-time Session Classification ----
st.subheader("Classify a New Session (Paste Command)")
session_input = st.text_area("Paste a single session command here:")

if st.button("Classify Command"):
    session_txt = (session_input or "").strip().lower()
    if not session_txt:
        st.warning("Please paste a session command to classify.")
    else:
        # Simple heuristic
        if any(k in session_txt for k in ["nmap", "masscan", "-sS", "-sV", " -p"]):
            hpred = "Port Scan"
        elif any(k in session_txt for k in ["nc -e", "/bin/sh", "python -c", "bash -i", "reverse shell"]):
            hpred = "Reverse Shell"
        elif any(k in session_txt for k in ["wget", "curl", "ftp", "download"]):
            hpred = "Malware Fetch / Payload Exec"
        elif any(k in session_txt for k in ["hydra", "john", "medusa", "sshpass", "brute force"]):
            hpred = "Brute Force"
        elif any(k in session_txt for k in ["grep password","cat /etc/passwd","id; uname","ps aux","whoami"]):
            hpred = "Recon / Info Gathering"
        else:
            hpred = "Unknown / Other"
        st.info(f"Heuristic Prediction: {hpred}")

# ---- ML Section (Random Forest in-memory) ----
st.subheader("Classify Uploaded or Sample Session Data (Random Forest)")

uploaded_file = st.file_uploader("Upload a CSV with session features", type="csv")
use_sample = st.checkbox("Use sample session data for testing")

df_test = None
if uploaded_file:
    df_test = pd.read_csv(uploaded_file)
elif use_sample:
    df_test = pd.DataFrame([{
        'failed_logins': 1,
        'commands_count': 3,
        'has_url': 1,
        'payload_hash_present': 0,
        'geo_lat': 40.24,
        'geo_lon': 116.65,
        'threat_score': 0.4
    }])

if df_test is not None:
    # Ensure all columns exist
    required_cols = ['failed_logins','commands_count','has_url','payload_hash_present','geo_lat','geo_lon','threat_score']
    for col in required_cols:
        if col not in df_test.columns:
            df_test[col] = 0

    # Prepare training data from loaded CSV
    if 'attack_type' in df.columns:
        df['attack_binary'] = df['attack_type'].apply(lambda x: 0 if x=='benign' else 1)
        X_train = df[required_cols]
        y_train = df['attack_binary']
        clf = RandomForestClassifier(n_estimators=100, random_state=42)
        clf.fit(X_train, y_train)
        preds = clf.predict(df_test[required_cols])
        df_test['ML_Prediction'] = preds
        st.dataframe(df_test)
    else:
        st.error("Cannot train model — main dataset missing 'attack_type' column")
#
