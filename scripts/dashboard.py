import streamlit as st
import pandas as pd
import plotly.express as px
import joblib
import openai
import os

# ---- Streamlit Page Setup ----
st.set_page_config(page_title="AI-Powered Honeypot Analytics Dashboard", layout="wide")
st.title("AI-Powered Honeypot Analytics Dashboard")

# ---- Load Data ----
logs_path = "data/honeypot_realistic_1000.csv"
df = pd.read_csv(logs_path)

st.subheader("Raw Honeypot Logs")
st.dataframe(df)

# ---- AI-Generated Report ----
st.subheader("AI-Generated Report")
try:
    openai.api_key = st.secrets["OPENAI_API_KEY"]  # or os.getenv("OPENAI_API_KEY")

    prompt = f"""
    You are a cybersecurity AI. Analyze the following dataset (1000 honeypot logs)
    and provide a short summary highlighting key trends in attack types, threat scores, and attacker locations.
    """

    response = openai.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}],
        temperature=0
    )

    ai_report = response.choices[0].message.content
    st.write(ai_report)

except Exception as e:
    st.error(f"GPT-3.5 failed to generate report: {e}")

# ---- Summary Charts ----
st.subheader("Attack Type Distribution")
attack_counts = df['attack_type'].value_counts()
fig1 = px.bar(
    x=attack_counts.index,
    y=attack_counts.values,
    labels={'x':'Attack Type','y':'Count'}
)
st.plotly_chart(fig1, use_container_width=True)

st.subheader("Threat Scores Distribution")
fig2 = px.histogram(df, x='threat_score', nbins=20, title="Threat Score Histogram")
st.plotly_chart(fig2, use_container_width=True)

st.subheader("Attacks by Country")
fig3 = px.scatter_geo(
    df, lat='geo_lat', lon='geo_lon',
    color='attack_type', size='threat_score',
    hover_name='src_ip', title="Global Attack Map"
)
st.plotly_chart(fig3, use_container_width=True)

# ---- Real-time Session Classification ----
st.subheader("Classify a New Session")
session_input = st.text_area("Paste session command here:")

if st.button("Classify"):
    st.info("Analyzing session...")

    # ---- Optional: ML Model Prediction ----
    try:
        model_path = "../models/honeypot_model.pkl"
        model = joblib.load(model_path)
        from sklearn.feature_extraction.text import CountVectorizer
        vect = CountVectorizer()
        X_demo = vect.fit_transform([session_input])
        pred = model.predict(X_demo)
        st.info(f"ML Model Prediction: {pred[0]}")
    except Exception as e:
        st.warning(f"ML Model not available or failed: {e}")
