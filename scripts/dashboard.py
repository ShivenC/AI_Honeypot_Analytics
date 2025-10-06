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

# ---- AI-Generated Report (GPT-5) ----
st.subheader("AI-Generated Report")
if st.button("Generate AI Report"):
    try:
        openai.api_key = st.secrets["OPENAI_API_KEY"]

        # ---- Local summary to reduce tokens ----
        attack_counts = df['attack_type'].value_counts().to_dict()
        threat_stats = df['threat_score'].describe().to_dict()
        top_locations = df[['geo_lat','geo_lon']].dropna().head(5).to_dict(orient='records')
        high_threat = df[df['threat_score'] >= 0.7].shape[0]

        local_summary = f"""
        Attack counts: {attack_counts}
        Threat score stats: mean {threat_stats['mean']:.2f}, max {threat_stats['max']:.2f}
        Top 5 locations (lat/lon): {top_locations}
        High threat sessions: {high_threat}
        Total sessions: {len(df)}
        """

        # ---- GPT-5 Prompt ----
        prompt = f"""
        You are a cybersecurity AI. Using the summary below, generate a concise 1-paragraph
        analysis of honeypot activity and list 5 key points for quick insights.

        Summary:
        {local_summary}
        """

        response = openai.chat.completions.create(
            model="gpt-5-mini",
            messages=[{"role": "user", "content": prompt}]
        )

        ai_report = response.choices[0].message.content
        st.success("AI Report Generated:")
        st.write(ai_report)

    except Exception as e:
        st.error(f"GPT-5 failed to generate report: {e}")

# ---- Summary Charts ----
st.subheader("Attack Type Distribution")
attack_counts = df['attack_type'].value_counts()
fig1 = px.bar(
    x=attack_counts.index,
    y=attack_counts.values,
    labels={'x': 'Attack Type', 'y': 'Count'}
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
