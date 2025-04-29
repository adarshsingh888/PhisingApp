from urllib.parse import urlparse
import pandas as pd
import pickle
from .feature_extraction import extract_features

# Load model and expected features
model = pickle.load(open("phisingproject/phishing_model.pkl", "rb"))
feature_columns = pickle.load(open("phisingproject/feature_columns.pkl", "rb"))

# Your full extract_features(url) function should already be defined here

# Improved URL Prediction
def predict_url(url):
    trusted_domains = ['kaggle.com', 'google.com', 'github.com']
    domain = urlparse(url).netloc

    if any(td in domain for td in trusted_domains):
        return f"✅ Legitimate (trusted domain)"

    features = extract_features(url)

    # Fill in missing features with 0
    for col in feature_columns:
        if col not in features:
            features[col] = 0

    df = pd.DataFrame([features])[feature_columns]

    # Get confidence
    prob = model.predict_proba(df)[0][1]
    result = model.predict(df)[0]

    if prob >= 0.7:
        return f"⚠️ Phishing! )"
    else:
        return f"✅ Legitimate)"
    