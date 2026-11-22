import json
import re
from pathlib import Path
import joblib
import pandas as pd
import streamlit as st
from url_features import LEXICAL_FEATURE_COLS, extract_url_lexical_features

st.set_page_config(
    page_title="ScamShield AI — Scam Message & Phishing Link Detector",
    page_icon="🛡️",
    layout="wide",
)

BASE_DIR = Path(__file__).resolve().parent.parent
MODELS_DIR = BASE_DIR / "models"
SMS_MODEL_PATH = MODELS_DIR / "scamshield_sms_model.joblib"
URL_MODEL_PATH = MODELS_DIR / "scamshield_url_model.joblib"
META_PATH = MODELS_DIR / "scamshield_metadata.json"

@st.cache_resource
def load_artifacts():
    sms_pipe = joblib.load(SMS_MODEL_PATH)
    url_pipe = joblib.load(URL_MODEL_PATH)
    meta = {}
    if META_PATH.exists():
        meta = json.loads(META_PATH.read_text(encoding="utf-8"))
    return sms_pipe, url_pipe, meta

def score_sms(text: str, model, low_th: float = 0.35, high_th: float = 0.65) -> dict:
    msg = text.strip()
    proba = float(model.predict_proba([msg])[0, 1])

    indicators = []
    lower_msg = msg.lower()
    if re.search(r"(?:https?://|www\.|bit\.ly|tinyurl\.com|cutt\.ly|rb\.gy)", lower_msg):
        indicators.append("Contains a web link or shortened URL.")
    if re.search(r"\b(?:bvn|nin|otp|pin|password|account\s*suspended|verify\s*account|update\s*kyc)\b", lower_msg):
        indicators.append("Mentions sensitive credentials, BVN/NIN/KYC, or urgent account action.")
    if re.search(r"\b(?:won|winner|claim|prize|bonus|free|airtime|cashback|grant|loan\s*approved)\b", lower_msg):
        indicators.append("Uses prize, freebie, reward, or financial lure phrasing.")
    if re.search(r"\b\d{10,11}\b", msg) or len(re.findall(r"\d", msg)) >= 6:
        indicators.append("Contains multiple digits, phone numbers, or numeric codes.")
    if re.search(r"\b(?:alert|acct|debited|credited|bal|ngn|₦)\b", lower_msg):
        indicators.append("Contains banking/transaction alert terms or currency markers.")
    if not indicators:
        indicators.append("No high-risk scam keywords or link patterns detected.")

    if proba >= high_th:
        status = "High Risk (Likely Scam / Spam)"
        confidence = proba
        warning = (
            "Note: Legitimate bank/transaction alerts with numbers and currency formatting can sometimes "
            "resemble spam patterns in international SMS training data."
            if re.search(r"\b(?:alert|acct|debited|credited|bal|ngn|₦)\b", lower_msg)
            else None
        )
        advice = "Do not click links, share your PIN/OTP/BVN/NIN, or call unverified numbers. Confirm via official channels."
    elif proba >= low_th:
        status = "Uncertain / Borderline"
        confidence = max(proba, 1.0 - proba)
        warning = (
            f"Borderline confidence (spam probability: {proba:.1%}). "
            "Short, conversational, or localized scam messages may sit near the classification boundary."
        )
        advice = "Treat with caution and verify the sender independently before acting or sharing information."
    else:
        status = "Low Risk (Likely Legitimate)"
        confidence = 1.0 - proba
        warning = (
            "Localized scam phrasing without classic spam keywords can still evade text-only classifiers."
            if proba > 0.05 else None
        )
        advice = "Always double-check unexpected requests for money, codes, or personal details."

    return {
        "status": status,
        "confidence": confidence * 100,
        "risk_prob": proba * 100,
        "indicators": indicators,
        "warning": warning,
        "advice": advice,
    }

def score_url(raw_url: str, model, low_th: float = 0.35, high_th: float = 0.65) -> dict:
    cleaned = raw_url.strip()
    parse_target = cleaned if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned) else f"http://{cleaned}"
    feats_dict = extract_url_lexical_features(parse_target)
    feats_df = pd.DataFrame([feats_dict])[LEXICAL_FEATURE_COLS]
    proba = float(model.predict_proba(feats_df)[0, 1])

    indicators = []
    if not cleaned.lower().startswith("https://"):
        indicators.append("Does not begin with https:// (or protocol was omitted).")
    if feats_dict["IsDomainIP"] == 1:
        indicators.append("Uses a raw IP address instead of a domain name.")
    if feats_dict["URLLength"] >= 60:
        indicators.append(f"Long URL string ({feats_dict['URLLength']} characters).")
    if feats_dict["NoOfSubDomain"] >= 2:
        indicators.append(f"Multiple subdomains ({feats_dict['NoOfSubDomain']}).")
    if feats_dict["NoOfDegitsInURL"] >= 4:
        indicators.append(f"Contains several digits ({feats_dict['NoOfDegitsInURL']}).")
    if feats_dict["HasObfuscation"] == 1:
        indicators.append("Contains percent-encoding (%xx) or '@' obfuscation characters.")
    if not indicators:
        indicators.append("URL lexical structure appears clean/standard.")

    if proba >= high_th:
        status = "High Risk (Likely Phishing)"
        confidence = proba
        warning = (
            "Lexical-only model warning: short or clean-looking apex domains (e.g., without 'www.') "
            "can occasionally trigger false positives in URL-only models."
        )
        advice = "Avoid entering passwords, banking credentials, or BVN/NIN details on unfamiliar links."
    elif proba >= low_th:
        status = "Uncertain / Borderline"
        confidence = max(proba, 1.0 - proba)
        warning = (
            f"Borderline lexical phishing score ({proba:.1%}). "
            "URL-only analysis does not fetch webpages or verify brand ownership."
        )
        advice = "Type the official website address directly in your browser rather than following the link."
    else:
        status = "Low Risk (Lexically Benign)"
        confidence = 1.0 - proba
        warning = (
            "Lexical-only check: a clean URL structure does not guarantee a newly registered or lookalike site is safe."
        )
        advice = "Verify the exact domain spelling before submitting sensitive information."

    return {
        "status": status,
        "confidence": confidence * 100,
        "risk_prob": proba * 100,
        "indicators": indicators,
        "warning": warning,
        "advice": advice,
        "features": feats_dict,
    }

st.title("🛡️ ScamShield AI")
st.caption(
    "Independent, zero-API Machine Learning detector for suspicious SMS/messages and phishing URLs "
    "(using lexical URL features only—no external webpage scraping)."
)

try:
    sms_model, url_model, metadata = load_artifacts()
except Exception as exc:
    st.error(f"Could not load trained models from `{MODELS_DIR}`: {exc}")
    st.stop()

with st.sidebar:
    st.header("Model & Detection Info")
    st.write(f"**SMS Model:** `{metadata.get('sms_model_type', 'MultinomialNB')}`")
    st.write(f"**URL Model:** `{metadata.get('url_model_type', 'HistGradientBoosting')}`")
    st.write("**URL Feature Mode:** URL-only lexical (18 features)")
    st.markdown("---")
    st.caption(
        "Benchmark training data comes from international public datasets (UCI SMS Spam & UCI PhiUSIIL). "
        "Always apply human judgment—especially for local/Nigerian contexts and financial alerts."
    )

tab_sms, tab_url = st.tabs(["💬 Message / SMS Checker", "🔗 Website URL Checker"])

with tab_sms:
    st.subheader("Check a Suspicious Message or SMS")
    sms_samples = [
        "-- Select a sample message --",
        "Dear customer, your BVN & NIN profile requires urgent update to avoid account restriction. Click https://ng-bank-verify.xyz/login",
        "Congratulations! Your MTN line won 500,000 Naira & 50GB data. Call 08090001111 now to claim your prize.",
        "Abeg, are you still coming to the office around 10am today? Let me know.",
    ]
    chosen_sms = st.selectbox("Quick test samples", sms_samples, key="sms_sample_select")
    default_sms = "" if chosen_sms.startswith("--") else chosen_sms
    sms_input = st.text_area("Paste message text", value=default_sms, height=120, placeholder="Paste an SMS, WhatsApp text, or alert here...")

    if st.button("Analyze Message", type="primary", key="btn_sms"):
        if not sms_input.strip():
            st.warning("Please paste a message before running analysis.")
        else:
            res = score_sms(sms_input, sms_model)
            c1, c2 = st.columns(2)
            c1.metric("Risk Classification", res["status"])
            c2.metric("Model Confidence", f"{res['confidence']:.1f}%", delta=f"Spam Prob: {res['risk_prob']:.1f}%")

            st.markdown("**Suspicious Indicators Identified:**")
            for item in res["indicators"]:
                st.write(f"- {item}")

            st.info(f"**Safety Advice:** {res['advice']}")
            if res["warning"]:
                st.warning(f"**Confidence & Context Warning:** {res['warning']}")

with tab_url:
    st.subheader("Check a Website URL (URL-Only Lexical Analysis)")
    url_samples = [
        "-- Select a sample URL --",
        "https://www.cbn.gov.ng",
        "http://gtbank-security-update-verify-2026.com/login.php?session=99812&user=1",
        "http://192.168.10.55/portal/auth/verify",
        "https://secure.login.update.account-ng-portal.com/signin?id=482910",
    ]
    chosen_url = st.selectbox("Quick test samples", url_samples, key="url_sample_select")
    default_url = "" if chosen_url.startswith("--") else chosen_url
    url_input = st.text_input("Paste website URL", value=default_url, placeholder="e.g., https://example.com/login")

    if st.button("Analyze URL", type="primary", key="btn_url"):
        if not url_input.strip():
            st.warning("Please paste a URL before running analysis.")
        else:
            res = score_url(url_input, url_model)
            c1, c2 = st.columns(2)
            c1.metric("Risk Classification", res["status"])
            c2.metric("Model Confidence", f"{res['confidence']:.1f}%", delta=f"Phish Prob: {res['risk_prob']:.1f}%")

            st.markdown("**Suspicious Indicators Identified:**")
            for item in res["indicators"]:
                st.write(f"- {item}")

            st.info(f"**Safety Advice:** {res['advice']}")
            if res["warning"]:
                st.warning(f"**Confidence & Limitation Warning:** {res['warning']}")

            with st.expander("View Extracted URL-Only Lexical Features"):
                st.dataframe(pd.DataFrame([res["features"]]).T.rename(columns={0: "Value"}), use_container_width=True)
