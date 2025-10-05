import streamlit as st
import pandas as pd
import plotly.express as px
import joblib

# ---- Load Data ----
st.title("AI-Powered Honeypot Analytics Dashboard")

# Load the logs/features
logs_path = "../data/honeypot_realistic_1000.csv"
df = pd.read_csv(logs_path)

st.subheader("Raw Honeypot Logs")
st.dataframe(df)

# ---- Summary Charts ----
st.subheader("Attack Type Distribution")
attack_counts = df['attack_type'].value_counts()
fig1 = px.bar(x=attack_counts.index, y=attack_counts.values, labels={'x':'Attack Type','y':'Count'})
st.plotly_chart(fig1)

st.subheader("Threat Scores Distribution")
fig2 = px.histogram(df, x='threat_score', nbins=20, title="Threat Score Histogram")
st.plotly_chart(fig2)

st.subheader("Attacks by Country")
fig3 = px.scatter_geo(df, lat='geo_lat', lon='geo_lon',
                      color='attack_type', size='threat_score',
                      hover_name='src_ip', title="Global Attack Map")
st.plotly_chart(fig3)

# ---- Real-time Session Classification ----
st.subheader("Classify a New Session")
session_input = st.text_area("Paste session command here:")

if st.button("Classify"):
    # Load model
    model = joblib.load("../models/honeypot_model.pkl")
    
    # For demo: simple vectorization (replace with your feature pipeline)
    from sklearn.feature_extraction.text import CountVectorizer
    vect = CountVectorizer()
    X_demo = vect.fit_transform([session_input])
    
    pred = model.predict(X_demo)
    st.write(f"Predicted attack type: {pred[0]}")
