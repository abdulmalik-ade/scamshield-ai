import json
import re
from pathlib import Path
import joblib
import pandas as pd
import streamlit as st
from url_features import LEXICAL_FEATURE_COLS, extract_url_lexical_features

st.set_page_config(
    page_title="ScamShield AI — Stay Safe From Scam Messages & Fake Links",
    page_icon="🛡️",
    layout="wide",
)

# --- Creator Contact Details (Update these with your live links) ---
CREATOR_NAME = "Abdulmalik Tajudeen"
PORTFOLIO_URL = "https://github.com/abdulmalik-ade.github.io"
LINKEDIN_URL = "https://www.linkedin.com"
#CONTACT_EMAIL = "abdulmalik@example.com"

BASE_DIR = Path(__file__).resolve().parent.parent
MODELS_DIR = BASE_DIR / "models"
SMS_MODEL_PATH = MODELS_DIR / "scamshield_sms_model.joblib"
URL_MODEL_PATH = MODELS_DIR / "scamshield_url_model.joblib"
META_PATH = MODELS_DIR / "scamshield_metadata.json"

st.markdown(
    """
    <style>
        .hero-box {
            padding: 1.35rem 1.5rem;
            border-radius: 14px;
            background: linear-gradient(135deg, #102a43 0%, #1d3557 100%);
            color: #ffffff;
            margin-bottom: 1.2rem;
            border: 1px solid rgba(255,255,255,0.08);
        }
        .hero-box h1 {
            margin: 0 0 0.35rem 0;
            font-size: 1.9rem;
            color: #ffffff;
        }
        .hero-box p {
            margin: 0;
            font-size: 1rem;
            color: #d9e2ec;
            line-height: 1.5;
        }
        .result-card {
            padding: 1.25rem 1.4rem;
            border-radius: 12px;
            margin-top: 0.75rem;
            margin-bottom: 1rem;
            border-left: 6px solid;
        }
        .card-high {
            background-color: rgba(220, 38, 38, 0.12);
            border-left-color: #ef4444;
        }
        .card-mid {
            background-color: rgba(245, 158, 11, 0.14);
            border-left-color: #f59e0b;
        }
        .card-low {
            background-color: rgba(16, 185, 129, 0.12);
            border-left-color: #10b981;
        }
        .result-title {
            font-size: 1.25rem;
            font-weight: 700;
            margin-bottom: 0.3rem;
        }
        .result-sub {
            font-size: 0.96rem;
            opacity: 0.92;
            margin: 0;
        }
        .footer-note {
            margin-top: 2.5rem;
            padding-top: 1rem;
            border-top: 1px solid rgba(128, 128, 128, 0.25);
            font-size: 0.88rem;
            opacity: 0.85;
            text-align: center;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


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

    findings = []
    lower_msg = msg.lower()
    if re.search(r"(?:https?://|www\.|bit\.ly|tinyurl\.com|cutt\.ly|rb\.gy)", lower_msg):
        findings.append("Includes a website link or shortened address.")
    if re.search(r"\b(?:bvn|nin|otp|pin|password|account\s*suspended|verify\s*account|update\s*kyc)\b", lower_msg):
        findings.append("Asks for sensitive details (like BVN, NIN, PIN, OTP) or pushes urgent account action.")
    if re.search(r"\b(?:won|winner|claim|prize|bonus|free|airtime|cashback|grant|loan\s*approved)\b", lower_msg):
        findings.append("Promises a prize, giveaway, free offer, or quick financial reward.")
    if re.search(r"\b\d{10,11}\b", msg) or len(re.findall(r"\d", msg)) >= 6:
        findings.append("Contains phone numbers, codes, or several numbers.")
    if not findings:
        findings.append("Reads like everyday text without common scam triggers.")

    if proba >= high_th:
        tier = "high"
        headline = "Likely a Scam or Unwanted Promo Message"
        summary = "This message shares strong patterns with scam or promotional spam texts."
        confidence = proba * 100
        tip = "Do not tap any links, reply with personal details, or share your PIN, OTP, BVN, or NIN. Confirm directly with the organization using an official contact."
        note = (
            "Heads-up: Legitimate bank debit/credit alerts with numbers and amounts can sometimes look similar to promo messages."
            if re.search(r"\b(?:alert|acct|debited|credited|bal|ngn|₦)\b", lower_msg)
            else None
        )
    elif proba >= low_th:
        tier = "mid"
        headline = "Proceed With Caution — Unclear Message"
        summary = "Some parts of this message are mixed or borderline, so it isn't clearly safe or clearly a scam."
        confidence = max(proba, 1.0 - proba) * 100
        tip = "Pause before responding or clicking anything. Verify who sent it through a trusted channel first."
        note = "Short or unfamiliar messages near the middle range deserve extra care."
    else:
        tier = "low"
        headline = "Looks Safe / Everyday Message"
        summary = "No strong scam warning signs stood out in this message."
        confidence = (1.0 - proba) * 100
        tip = "Even when a message looks normal, never share passwords, OTPs, or banking details with unexpected senders."
        note = None

    return {
        "tier": tier,
        "headline": headline,
        "summary": summary,
        "confidence": confidence,
        "findings": findings,
        "tip": tip,
        "note": note,
    }


def score_url(raw_url: str, model, low_th: float = 0.35, high_th: float = 0.65) -> dict:
    cleaned = raw_url.strip()
    parse_target = cleaned if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned) else f"http://{cleaned}"
    feats_dict = extract_url_lexical_features(parse_target)
    feats_df = pd.DataFrame([feats_dict])[LEXICAL_FEATURE_COLS]
    proba = float(model.predict_proba(feats_df)[0, 1])

    findings = []
    if not cleaned.lower().startswith("https://"):
        findings.append("Does not use https:// (or the web address was entered without https://).")
    if feats_dict["IsDomainIP"] == 1:
        findings.append("Uses raw numbers (an IP address) instead of a normal website name.")
    if feats_dict["URLLength"] >= 60:
        findings.append("The web address is unusually long.")
    if feats_dict["NoOfSubDomain"] >= 2:
        findings.append("Has extra chained sub-addresses (subdomains) before the main name.")
    if feats_dict["NoOfDegitsInURL"] >= 4:
        findings.append("Contains several numbers inside the link.")
    if feats_dict["HasObfuscation"] == 1:
        findings.append("Contains encoded or unusual symbols (% or @) often used to mask destinations.")
    if not findings:
        findings.append("The structure of the web address looks straightforward.")

    if proba >= high_th:
        tier = "high"
        headline = "High Risk — Suspicious Web Link"
        summary = "The structure of this link matches patterns commonly seen in phishing or deceptive URLs."
        confidence = proba * 100
        tip = "Avoid logging in or entering card, bank, BVN, or NIN details here. Open the official website on your own instead."
        note = "This check inspects the link text alone without visiting the page—short main domains without 'www.' can occasionally be flagged."
    elif proba >= low_th:
        tier = "mid"
        headline = "Uncertain Link — Double-Check Before Opening"
        summary = "This link sits on the fence and needs a closer look before you trust it."
        confidence = max(proba, 1.0 - proba) * 100
        tip = "Check the exact spelling of the website name and avoid entering sensitive info on unfamiliar pages."
        note = "Link-only checks cannot see what is displayed on a webpage or confirm who owns a new domain."
    else:
        tier = "low"
        headline = "Link Structure Looks Normal"
        summary = "Nothing in the web address itself raised a strong phishing alarm."
        confidence = (1.0 - proba) * 100
        tip = "Always check the exact website name carefully—scammers sometimes register lookalike addresses."
        note = "A normal-looking link still cannot guarantee a brand-new or impersonating website is safe."

    return {
        "tier": tier,
        "headline": headline,
        "summary": summary,
        "confidence": confidence,
        "findings": findings,
        "tip": tip,
        "note": note,
    }


def render_result(res: dict):
    card_class = {"high": "card-high", "mid": "card-mid", "low": "card-low"}[res["tier"]]
    st.markdown(
        f"""
        <div class="result-card {card_class}">
            <div class="result-title">{res["headline"]}</div>
            <p class="result-sub">{res["summary"]}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.write(f"**How sure is this check?** {res['confidence']:.0f}%")
    st.progress(min(max(res["confidence"] / 100.0, 0.0), 1.0))

    st.markdown("**What we noticed:**")
    for item in res["findings"]:
        st.write(f"- {item}")

    st.success(f"**Recommended next step:** {res['tip']}")
    if res["note"]:
        st.caption(f"💡 {res['note']}")


# --- Sidebar: Quick Safety Guide + Creator Info ---
with st.sidebar:
    st.markdown("### 🛡️ Quick Safety Reminders")
    st.write("- Banks and telecoms won't ask for your PIN, OTP, BVN, or NIN via a random link.")
    st.write("- Be extra careful with urgent "account blocked" or "you won a prize" alerts.")
    st.write("- When in doubt, open your official app or browser directly.")

    st.markdown("---")
    st.markdown(f"### Created by {CREATOR_NAME}")
    st.write(f"[Portfolio]({PORTFOLIO_URL}) · [LinkedIn]({LINKEDIN_URL})")
    st.write(f"Email: `{CONTACT_EMAIL}`")


# --- Hero Banner ---
st.markdown(
    """
    <div class="hero-box">
        <h1>🛡️ Welcome to ScamShield AI</h1>
        <p>Paste a suspicious text message or website link below to check for common scam and phishing warning signs in seconds.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

try:
    sms_model, url_model, _ = load_artifacts()
except Exception:
    st.error("We're having trouble loading the safety checker right now. Please refresh or try again shortly.")
    st.stop()

tab_sms, tab_url = st.tabs(["💬 Check a Message", "🔗 Check a Website Link"])

with tab_sms:
    st.subheader("Paste a Text, WhatsApp Message, or Alert")
    sms_samples = [
        "-- Try an example message --",
        "Dear customer, your BVN & NIN profile requires urgent update to avoid account restriction. Click https://ng-bank-verify.xyz/login",
        "Congratulations! Your line won ₦500,000 & 50GB data. Call 08090001111 now to claim your prize.",
        "Hey, are we still meeting at 10am today? Let me know when you're heading out.",
    ]
    chosen_sms = st.selectbox("Sample messages", sms_samples, key="sms_sample")
    default_sms = "" if chosen_sms.startswith("--") else chosen_sms
    sms_input = st.text_area(
        "Message text",
        value=default_sms,
        height=120,
        placeholder="Paste the message you received...",
        label_visibility="collapsed",
    )

    if st.button("Check Message", type="primary", key="check_sms_btn"):
        if not sms_input.strip():
            st.warning("Paste a message above first so I can check it for you.")
        else:
            render_result(score_sms(sms_input, sms_model))

with tab_url:
    st.subheader("Paste a Website Link")
    url_samples = [
        "-- Try an example link --",
        "https://www.cbn.gov.ng",
        "http://gtbank-security-update-verify-2026.com/login.php?session=99812&user=1",
        "http://192.168.10.55/portal/auth/verify",
    ]
    chosen_url = st.selectbox("Sample links", url_samples, key="url_sample")
    default_url = "" if chosen_url.startswith("--") else chosen_url
    url_input = st.text_input(
        "Website link",
        value=default_url,
        placeholder="Paste a link like https://example.com...",
        label_visibility="collapsed",
    )

    if st.button("Check Link", type="primary", key="check_url_btn"):
        if not url_input.strip():
            st.warning("Paste a website link above first so I can check it for you.")
        else:
            render_result(score_url(url_input, url_model))

# --- Clean Footer ---
st.markdown(
    f"""
    <div class="footer-note">
        Built by <strong>Abdulmalik Tajudeen</strong> ·
        <a href="https://github.com/abdulmalik-ade.github.io" target="_blank">Portfolio</a> ·
        <a href="https://www.linkedin.com/in/abdulmalik-tajudeen-86602b38b/" target="_blank">LinkedIn</a> ·
        <a href="mailto:CONTACT_EMAIL">abdulmaliktajudeen5@gmail.com</a>
    </div>
    """,
    unsafe_allow_html=True,
)
