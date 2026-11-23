# 🛡️ ScamShield AI
### AI-Powered Scam Message & Phishing Link Detection

**Identify suspicious messages. Examine potentially dangerous links. Make safer digital decisions.**

ScamShield AI is a machine learning-powered web application designed to help users identify common warning signs in suspicious text messages and potentially malicious website URLs.

The application combines two independently trained machine learning models in one simple interface. Users can paste a message or website address, run an analysis, and receive a risk assessment alongside relevant warning indicators and practical safety recommendations.

**Live Application:** https://scamshield-check.onrender.com/  
**GitHub Repository:** https://github.com/abdulmalik-ade/scamshield-ai

---

## 📸 Application Preview

### Phishing URL Detection Interface

![ScamShield AI phishing URL detection interface](assets/scamshield-url-check.png)

The URL detection interface allows users to submit a website address and examine its structure for common phishing-related warning signs. The application presents a risk assessment, model confidence, observations, and recommended safety actions.

> **Screenshot setup:** Create an `assets` folder in the repository and upload the application screenshot using the filename `scamshield-url-check.png`. Then this image will display automatically in the README.

---

## 🎯 The Problem

Online scams increasingly use deceptive messages and fraudulent websites to trick people into revealing sensitive information, making payments, or interacting with malicious links.

Examples include:

- Fake bank alerts and account security messages.
- Messages claiming that an account has been blocked.
- Fraudulent prize and giveaway notifications.
- Suspicious links designed to imitate trusted websites.
- Messages using urgency, fear, or unrealistic promises to influence decisions.

Many users find it difficult to distinguish suspicious messages from legitimate communication.

ScamShield AI addresses this challenge by providing an accessible machine learning-based tool that examines message content and URL structure for suspicious patterns.

## 💡 What ScamShield AI Does

The application provides two independent detection capabilities.

### 1. SMS & Message Detection

Users can paste a suspicious SMS or text message into the application for analysis.

The message classifier examines textual patterns and language commonly associated with spam and suspicious messages.

**What users receive:**
- A risk classification.
- Model confidence information.
- Relevant suspicious indicators.
- Practical safety recommendations.

The message classifier uses a **Multinomial Naive Bayes model with TF-IDF n-gram text features**, trained on the UCI SMS Spam Collection.

### 2. Phishing Website URL Detection

Users can paste a website address into the application to examine its URL structure.

The URL classifier evaluates 18 lexical features derived directly from the submitted URL.

Examples of characteristics examined include:
- URL length and structural complexity.
- Unusual characters and symbols.
- Suspicious URL patterns.
- Domain and subdomain structure.
- Other lexical indicators associated with phishing URLs.

**What users receive:**
- A URL risk assessment.
- Model confidence information.
- Detected URL warning indicators.
- Recommended next steps.

The URL classifier uses a **HistGradientBoostingClassifier** trained on the UCI PhiUSIIL Phishing URL Dataset.

Importantly, the application does not visit submitted websites or inspect their live webpage content.

---

## 🖥️ Understanding the Interface

ScamShield AI is designed to keep the checking process straightforward.

### Welcome Section

The welcome section introduces the application and explains its main purpose. Users can quickly understand that the tool supports both suspicious message analysis and website link checking.

### Check a Message

Select the **Check a Message** tab to analyse suspicious text.

Paste the message into the input area and submit it for assessment. The application processes the text using its trained message classification pipeline and presents the result.

### Check a Website Link

Select the **Check a Website Link** tab to examine a URL.

Paste the website address into the input field and select **Check Link**. The application analyses its URL structure and presents the assessment.

### Risk Assessment Results

Depending on the model's assessment, the application can display:

- **High Risk:** The submitted content contains patterns associated with suspicious or potentially harmful activity.
- **Uncertain / Borderline:** The model cannot make a sufficiently confident classification. Additional verification is recommended.
- **Low Risk:** The model did not identify strong warning signs in the submitted content.

Results may also include model confidence, observations, and recommended safety actions.

**A low-risk result does not mean that a message or website is guaranteed to be safe.**

### Quick Safety Reminders

The sidebar provides practical reminders to help users recognise common scam tactics, including requests for PINs, OTPs, BVNs, and NINs through suspicious links.

It also encourages users to access official websites and applications directly rather than relying on unverified links.

---

## 🧠 Machine Learning Architecture

ScamShield AI uses two independent machine learning pipelines rather than attempting to solve both tasks with a single model.

| Component | Message Detection | URL Detection |
|---|---|---|
| Algorithm | Multinomial Naive Bayes | HistGradientBoostingClassifier |
| Feature extraction | TF-IDF n-grams | 18 lexical URL features |
| Training dataset | UCI SMS Spam Collection | UCI PhiUSIIL Phishing URL Dataset |
| Deduplicated records | 5,158 | 235,370 |
| Prediction input | Message text | Website URL |

### Why Two Independent Models?

Messages and website addresses have different characteristics.

A message classifier needs to understand textual patterns, word combinations, and suspicious language. A URL classifier needs to examine structural and lexical characteristics of website addresses.

Using separate models allows each detection task to use an appropriate feature extraction method and classification algorithm.

### No Paid Prediction APIs

Both models are trained machine learning pipelines that are stored with the application.

At prediction time:
- The application loads its saved models.
- User input is processed by the appropriate model.
- Predictions are generated without requiring paid AI APIs.
- The URL checker does not fetch or visit submitted websites.
- No external webpage inspection service is required.

---

## 📊 Model Performance & Evaluation

Both models were evaluated using held-out test data.

### Held-Out Test Results

| Evaluation Metric | SMS / Message Classifier | Phishing URL Classifier |
|---|---:|---:|
| Accuracy | **98.26%** | **99.64%** |
| Precision | 100.00% | 99.82% |
| Recall | 85.94% | 99.34% |
| F1-score | 0.9244 | 0.9958 |
| ROC-AUC | 0.9861 | 0.9983 |
| Evaluation records | 5,158 dataset records* | 235,370 dataset records* |

*The record counts above refer to the deduplicated datasets used for model development, not the number of records in the held-out test partitions.*

### What Do These Metrics Mean?

- **Accuracy:** The proportion of predictions that were correct.
- **Precision:** How often predictions of the positive class were correct.
- **Recall:** How much of the actual positive class the model successfully identified.
- **F1-score:** A balance between precision and recall.
- **ROC-AUC:** How effectively the model distinguishes between the two classes across classification thresholds.

### Interpreting the Results

The SMS classifier achieved 98.26% accuracy and 100% precision on its held-out benchmark, with a recall of 85.94%.

This means that its benchmark performance was strong, but it did not identify every spam message in the test data.

The phishing URL classifier achieved 99.64% accuracy, 99.82% precision, and 99.34% recall on its held-out benchmark.

These results demonstrate strong performance on the datasets used for evaluation. They should not be interpreted as a guarantee of equivalent performance on every new message, website, country, or scam technique.

**Important:** Dataset benchmark performance is not the same as real-world fraud detection accuracy. Actual performance can change when the application encounters messages and URLs that differ from its training data.

---

## ⚠️ Known Limitations & Responsible Use

ScamShield AI is a decision-support tool, not a replacement for independent verification or professional cybersecurity investigation.

### 1. Nigerian Banking Message Limitations

The SMS training dataset is an international collection rather than a dataset specifically designed around Nigerian banking communication.

Approximately 94% of spam messages in the training corpus contain digits. Consequently, legitimate Nigerian bank debit and credit alerts containing account numbers, transaction references, or currency amounts may sometimes trigger false-positive classifications.

Users should not assume that a message is fraudulent simply because it receives a high-risk assessment.

### 2. URL-Only Analysis

The phishing model examines URL-derived lexical features. It does not inspect live website content, certificates, hosting infrastructure, or domain registration history.

A newly registered malicious domain with an ordinary-looking URL may therefore escape detection.

Similarly, a legitimate website with an unusual URL structure may receive a suspicious assessment.

### 3. Dataset Generalisation

The models were trained on publicly available datasets. Their performance may differ when applied to new scam techniques, regional communication patterns, or previously unseen examples.

### 4. Confidence Is Not a Safety Guarantee

Model confidence describes the model's assessment under its learned patterns. It is not a verified probability that a message or website is safe.

**Always verify important financial, employment, and account-related communication through official channels. Never share your PIN, password, OTP, BVN, or other sensitive information through an unverified link.**

---

## 🛠️ Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core development language |
| Scikit-learn | Machine learning and model pipelines |
| Pandas | Dataset processing |
| NumPy | Numerical operations |
| TF-IDF | Message feature extraction |
| NLTK | Text preprocessing |
| Joblib | Saving and loading trained models |
| Streamlit | Interactive web application |
| Render | Application hosting |

---

## 📂 Repository Structure

```text
scamshield-ai/
│
├── models/
│   ├── scamshield_sms_model.joblib
│   ├── scamshield_url_model.joblib
│   └── scamshield_metadata.json
│
├── streamlit_app/
│   ├── app.py
│   ├── url_features.py
│   └── requirements.txt
│
├── assets/
│   └── scamshield-url-check.png
│
└── README.md
```

---

## 🚀 Run ScamShield AI Locally

You can run the application on your own computer.

### 1. Clone the repository

```bash
git clone https://github.com/abdulmalik-ade/scamshield-ai.git
```

### 2. Enter the project directory

```bash
cd scamshield-ai
```

### 3. Install the dependencies

```bash
pip install -r streamlit_app/requirements.txt
```

### 4. Start the Streamlit application

```bash
streamlit run streamlit_app/app.py
```

The application will open in your browser.

**Note:** The trained model files inside the `models` directory are required for predictions.

---

## 📚 Datasets & References

This project uses two publicly available datasets:

**1. UCI SMS Spam Collection**

Used to train the SMS and message classification model.

Dataset: https://archive.ics.uci.edu/dataset/228/sms

**2. UCI PhiUSIIL Phishing URL Dataset**

Used to train the phishing URL classification model.

Dataset: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset

The datasets are used for research and model development. Please consult their original documentation for licensing, citation, and usage requirements.

---

## 🔒 Privacy & Security Considerations

ScamShield AI does not require users to connect personal accounts or provide API keys.

The models perform inference without calling external AI prediction APIs or visiting submitted URLs.

However, when using the hosted application, submitted text and URLs are sent to the application server for processing. Users should avoid entering passwords, OTPs, PINs, account credentials, or other confidential information.

---

## 👨‍💻 Author

**Abdulmalik Tajudeen**

Data Analyst | Python Developer | Machine Learning Enthusiast

- **Portfolio:** https://abdulmalik-ade.github.io
- **GitHub:** https://github.com/abdulmalik-ade
- **LinkedIn:** [Connect with me on LinkedIn](https://www.linkedin.com/)
  
---

## ⭐ Project Overview

ScamShield AI demonstrates the practical application of machine learning to a real-world digital safety problem.

The project brings together:
- Two independently trained classification models.
- Text and URL feature engineering.
- Machine learning evaluation.
- Model serialization and deployment.
- An interactive Streamlit interface.
- Human-centred risk communication.
- Responsible discussion of model limitations.

The goal is simple: make machine learning useful and accessible by helping people recognise suspicious digital communication and make more informed decisions.

**If you find this project useful, consider giving the repository a ⭐ on GitHub.**

---

*Disclaimer: ScamShield AI is an educational and informational tool. It does not guarantee the detection of all scams, phishing websites, or fraudulent messages.*
