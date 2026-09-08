"""Streamlit bootstrap for the analyst interface."""

import os

import httpx
import streamlit as st

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000").rstrip("/")

st.set_page_config(page_title="Investigation Agent", page_icon="🔎", layout="wide")
st.title("Investigation Agent")
st.caption("AI-assisted, evidence-grounded SOC incident investigation")

try:
    response = httpx.get(f"{BACKEND_URL}/health", timeout=5)
    response.raise_for_status()
    health = response.json()
except (httpx.HTTPError, ValueError) as exc:
    st.error(f"Backend unavailable: {exc.__class__.__name__}")
else:
    if health["status"] == "ok":
        st.success("Backend, PostgreSQL, and Qdrant are ready.")
    else:
        st.warning("Backend is running, but one or more dependencies are unavailable.")
    st.json(health)

st.info("Checkpoint 0 bootstrap. Analyst workflow pages arrive after the core pipeline.")
