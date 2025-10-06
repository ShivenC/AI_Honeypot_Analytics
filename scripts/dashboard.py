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

# ---- Summary Charts ----
st.subheader("Attack Type Distribution")
attack_counts = df['attack_type'].value_counts()
fig1 = px.bar(x=attack_counts.index, y=attack_counts.values, labels={'x':'Attack Type','y':'Count'})
st.plotly_chart(fig1, use_container_width=True)

st.subheader("Threat Scores Distribution")
fig2 = px.histogram(df, x='threat_score', nbins=20, title="Threat Score Histogram")
st.plotly_chart(fig2, use_container_width=True)

st.subheader("Attacks by Country")
fig3 = px.scatter_geo(df, lat='geo_lat', lon='geo_lon',
                      color='attack_type', size='threat_score',
                      hover_name='src_ip', title="Global Attack Map")
st.plotly_chart(fig3, use_container_width=True)

# ---- AI-Generated Summary Report ----
st.subheader("AI-Generated Report")

try:
    # Use your API key from environment variable
    openai.api_key = os.getenv("OPENAI_API_KEY")  # Make sure you set it in Streamlit Cloud secrets

    # Prepare a short summary of stats to send to GPT
    summary_text = f"""
    Attack types and counts: {attack_counts.to_dict()}
    Threat score: min={df['threat_score'].min()}, max={df['threat_score'].max()}, mean={df['threat_score'].mean():.2f}
    Total sessions: {len(df)}
    """

    prompt = f"""
    You are a cybersecurity analyst AI. Based on the following honeypot log summary,
    write a short, clear analysis report in plain English highlighting attack trends and potential threats:

    {summary_text}
    """

    response = openai.ChatCompletion.create(
        model="gpt-5-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.5
    )

    ai_report = response['choices'][0]['message']['content'].strip()
    st.info(ai_report)

except Exception as e:
    st.error(f"GPT-5 failed to generate report: {e}")
