# scamshield-ai# 🛡️ ScamShield AI

**AI-Powered Scam Message & Phishing Link Detection**  
A self-contained, zero-API Machine Learning web application that evaluates suspicious SMS/text messages and website URLs using locally trained Scikit-Learn pipelines.

---

## Architecture & Design Decisions

1. **Dual Independent Models**
   - **SMS / Message Classifier (`MultinomialNB` + TF-IDF n-grams):** Trained on the UCI SMS Spam Collection (5,158 deduplicated messages).
   - **Phishing URL Classifier (`HistGradientBoostingClassifier`):** Trained on the UCI PhiUSIIL Phishing URL Dataset (235,370 deduplicated URLs) using **18 URL-only lexical features**.
2. **Zero External Dependencies at Inference**
   - Webpage/DOM features from PhiUSIIL are intentionally excluded so the app never fetches live suspicious URLs or relies on paid third-party APIs.
3. **Human-Centered Risk Output**
   - Displays Risk Classification (`High Risk`, `Uncertain / Borderline`, `Low Risk`), Model Confidence, Suspicious Indicators, Safety Advice, and explicit confidence/limitation warnings.

---

## Held-Out Test Benchmark Performance

| Model | Dataset (Deduplicated) | Accuracy | Precision | Recall | F1-Score | ROC-AUC |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **MultinomialNB (TF-IDF)** | UCI SMS Spam (`N = 5,158`) | 98.26% | 100.00% | 85.94% | 0.9244 | 0.9861 |
| **HistGradientBoosting (18 Lexical Features)** | UCI PhiUSIIL URLs (`N = 235,370`) | 99.64% | 99.82% | 99.34% | 0.9958 | 0.9983 |

---

## Known Limitations & Local Testing Insights

- **Domain Shift on Transactional Bank Alerts:** Because ~94% of spam in the international UCI SMS training corpus contains digits, legitimate Nigerian bank debit/credit alerts containing account numbers and currency amounts can trigger false positives.
- **URL-Only Lexical Boundaries:** Without live webpage inspection, short apex domains without `www.` (e.g., `https://paystack.com`) or newly registered lookalike domains with clean URL strings can diverge from lexical expectations.

---

## Repository Structure

```text
scamshield-ai/
├── models/
│   ├── scamshield_sms_model.joblib
│   ├── scamshield_url_model.joblib
│   └── scamshield_metadata.json
├── streamlit_app/
│   ├── app.py
│   ├── url_features.py
│   └── requirements.txt
└── README.md
