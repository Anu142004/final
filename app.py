import streamlit as st
import requests
import json
import time
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from urllib.parse import urlparse
import re
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import ipaddress
import tldextract
import io

# Set page configuration
st.set_page_config(
    page_title="Advanced Phishing URL Detector",
    page_icon="🔒",
    layout="wide"
)

# Custom CSS for enhanced styling
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        color: #1E88E5;
        text-align: center;
        margin-bottom: 2rem;
        background: linear-gradient(135deg, #1E88E5 0%, #0D47A1 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: 800;
    }
    .sub-header {
        font-size: 1.8rem;
        color: #0D47A1;
        border-bottom: 2px solid #0D47A1;
        padding-bottom: 0.5rem;
        margin-top: 2rem;
        margin-bottom: 1rem;
    }
    .result-box {
        padding: 20px;
        border-radius: 10px;
        margin: 20px 0;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    .safe {
        background: linear-gradient(135deg, #E8F5E9 0%, #C8E6C9 100%);
        border-left: 5px solid #4CAF50;
    }
    .phishing {
        background: linear-gradient(135deg, #FFEBEE 0%, #FFCDD2 100%);
        border-left: 5px solid #F44336;
    }
    .feature-positive {
        color: #F44336;
        font-weight: bold;
    }
    .feature-negative {
        color: #4CAF50;
        font-weight: bold;
    }
    .confidence-meter {
        height: 20px;
        background-color: #f5f5f5;
        border-radius: 10px;
        margin: 10px 0;
    }
    .confidence-fill {
        height: 100%;
        border-radius: 10px;
        text-align: center;
        color: white;
        line-height: 20px;
    }
    .info-box {
        background: linear-gradient(135deg, #E3F2FD 0%, #BBDEFB 100%);
        padding: 15px;
        border-radius: 10px;
        margin: 10px 0;
        border-left: 5px solid #2196F3;
    }
    .training-box {
        background: linear-gradient(135deg, #FFF3E0 0%, #FFE0B2 100%);
        padding: 20px;
        border-radius: 10px;
        margin: 15px 0;
        border-left: 5px solid #FF9800;
    }
</style>
""", unsafe_allow_html=True)

# Header
st.markdown('<h1 class="main-header">🔒 Advanced Phishing URL Detector</h1>', unsafe_allow_html=True)
st.markdown("""
<div style="text-align: center; margin-bottom: 2rem;">
    <p>Machine Learning-powered tool for detecting phishing URLs with real-time analysis</p>
</div>
""", unsafe_allow_html=True)

# Initialize session state
if 'history' not in st.session_state:
    st.session_state.history = []
if 'model' not in st.session_state:
    st.session_state.model = None
if 'model_trained' not in st.session_state:
    st.session_state.model_trained = False
if 'training_data' not in st.session_state:
    st.session_state.training_data = None
if 'accuracy' not in st.session_state:
    st.session_state.accuracy = 0
if 'uploaded_data' not in st.session_state:
    st.session_state.uploaded_data = None

# Feature extraction functions
def normalize_url(url):
    """Normalize URL by converting to lowercase and adding scheme if missing"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url.lower()

def extract_features(url):
    """Extract features from URL for ML model"""
    features = {}
    
    # Normalize URL first
    normalized_url = normalize_url(url)
    
    # URL-based features
    features['url_length'] = len(normalized_url)
    features['num_digits'] = sum(c.isdigit() for c in normalized_url)
    features['num_letters'] = sum(c.isalpha() for c in normalized_url)
    features['num_special_chars'] = len(normalized_url) - features['num_digits'] - features['num_letters']
    features['digit_ratio'] = features['num_digits'] / len(normalized_url) if len(normalized_url) > 0 else 0
    features['letter_ratio'] = features['num_letters'] / len(normalized_url) if len(normalized_url) > 0 else 0
    features['special_char_ratio'] = features['num_special_chars'] / len(normalized_url) if len(normalized_url) > 0 else 0
    
    # Domain-based features
    try:
        parsed_url = urlparse(normalized_url)
        domain = parsed_url.netloc
        
        # Check if domain is IP address
        try:
            ipaddress.ip_address(domain)
            features['is_ip'] = 1
        except:
            features['is_ip'] = 0
            
        # TLD features
        extracted = tldextract.extract(normalized_url)
        features['tld_length'] = len(extracted.suffix)
        features['domain_length'] = len(extracted.domain)
        features['subdomain_length'] = len(extracted.subdomain)
        features['subdomain_count'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
        
        # Check for @ symbol
        features['has_at_symbol'] = 1 if '@' in normalized_url else 0
        
        # Check for redirects
        features['has_redirect'] = 1 if '//' in normalized_url[8:] else 0
        
        # Check for HTTPS
        features['uses_https'] = 1 if normalized_url.startswith('https') else 0
        
        # Check for hyphen in domain
        features['has_hyphen'] = 1 if '-' in extracted.domain else 0
        
        # Check for mixed case in original URL (phishing technique)
        features['has_mixed_case'] = 1 if any(c.islower() and any(d.isupper() for d in url) for c in url) else 0
        
        # Check for multiple subdomains
        features['multiple_subdomains'] = 1 if extracted.subdomain.count('.') >= 2 else 0
        
        # Check for port number
        features['has_port'] = 1 if ':' in domain and domain.split(':')[1].isdigit() else 0
        
        # Check for file extension
        path = parsed_url.path
        features['has_file_extension'] = 1 if '.' in path.split('/')[-1] and len(path.split('/')[-1].split('.')[-1]) <= 5 else 0
        
    except:
        # Default values if parsing fails
        features['is_ip'] = 0
        features['tld_length'] = 0
        features['domain_length'] = 0
        features['subdomain_length'] = 0
        features['subdomain_count'] = 0
        features['has_at_symbol'] = 0
        features['has_redirect'] = 0
        features['uses_https'] = 0
        features['has_hyphen'] = 0
        features['has_mixed_case'] = 0
        features['multiple_subdomains'] = 0
        features['has_port'] = 0
        features['has_file_extension'] = 0
    
    # Suspicious keywords
    suspicious_keywords = ['login', 'verify', 'account', 'security', 'confirm', 'banking', 
                          'paypal', 'apple', 'amazon', 'ebay', 'update', 'password', 'credential',
                          'alert', 'secure', 'validation', 'authentication', 'signin', 'bank', 'online',
                          'webscr', 'signin', 'login', 'verify', 'account', 'secure', 'confirm', 'validation']
    
    features['suspicious_keyword_count'] = sum(1 for keyword in suspicious_keywords if keyword in normalized_url)
    
    # Character patterns
    features['repeat_characters'] = 1 if re.search(r'(.)\1{3,}', normalized_url) else 0  # 4 or more repeating characters
    
    # Check for known legitimate domains with mixed case (like the examples provided)
    known_legitimate_domains = ['google.com', 'facebook.com', 'microsoft.com', 'apple.com', 
                               'amazon.com', 'netflix.com', 'github.com', 'twitter.com',
                               'paypal.com', 'linkedin.com', 'instagram.com', 'yahoo.com']
    
    extracted_domain = f"{extracted.domain}.{extracted.suffix}"
    features['mixed_case_legitimate_domain'] = 0
    if features['has_mixed_case'] and extracted_domain in known_legitimate_domains:
        features['mixed_case_legitimate_domain'] = 1
    
    # Entropy calculation (higher entropy might indicate random-looking domains)
    from math import log2
    if len(normalized_url) > 0:
        prob = [float(normalized_url.count(c)) / len(normalized_url) for c in dict.fromkeys(list(normalized_url))]
        features['entropy'] = sum([p * log2(1/p) for p in prob])
    else:
        features['entropy'] = 0
    
    # Check for URL shortening services
    shortening_services = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co', 'is.gd', 'buff.ly', 'adf.ly', 'bit.do']
    features['is_shortened'] = 1 if any(service in normalized_url for service in shortening_services) else 0
    
    # Check for excessive special characters
    features['excessive_special_chars'] = 1 if features['special_char_ratio'] > 0.3 else 0
    
    return features

# Function to generate synthetic dataset for training
def generate_training_data():
    """Generate synthetic training data for demonstration"""
    # This would normally come from a Kaggle dataset
    # For demo purposes, we'll create a synthetic dataset
    
    # Sample legitimate URLs
    legitimate_urls = [
        "https://www.google.com",
        "https://www.github.com",
        "https://www.microsoft.com",
        "https://www.amazon.com",
        "https://www.netflix.com",
        "https://www.linkedin.com",
        "https://www.wikipedia.org",
        "https://www.reddit.com",
        "https://www.instagram.com",
        "https://www.twitter.com",
        "https://www.apple.com",
        "https://www.stackoverflow.com",
        "https://www.youtube.com",
        "https://www.medium.com",
        "https://www.quora.com",
        "https://www.paypal.com",
        "https://www.dropbox.com",
        "https://www.adobe.com",
        "https://www.spotify.com",
        "https://www.nytimes.com"
    ]
    
    # Sample phishing URLs (including mixed case examples)
    phishing_urls = [
        "https://facebook-security-alert-verify.com",
        "http://paypal-confirm-account.secure-login.com",
        "https://apple-id-verification-center.com",
        "https://netflix-renew-your-subscription.xyz",
        "https://microsoft-account-security.verify-info.com",
        "https://login-facebook.security-verification.com",
        "http://paypal-confirmation.secure-login.net",
        "https://apple-verify-account.info",
        "https://amazon-payment-update.com",
        "https://microsoft-account-security.verify.xyz",
        "https://google-login-security.verification.com",
        "https://bankofamerica-secure-login.com",
        "https://wellsfargo-online-banking.secure.com",
        "https://chase-online-login.verification.com",
        "https://twitter-account-confirmation.com",
        "https://www.gooGle.com",  # Mixed case example
        "https://www.goOglE.com",  # Mixed case example
        "https://www.faceBook.com",  # Mixed case example
        "https://www.appLe.com",  # Mixed case example
        "https://secure-paypal-login.verify-account.com",
        "https://update-your-account-info.secure-banking.com",
        "https://verify-identity-appleid.xyz",
        "http://login-microsoft-online.security-check.net",
        "https://amazon-account-security-alert.verification-portal.com",
        "https://netflix-payment-update.secure-login.org",
        "https://linkedin-profile-verification.confirm-identity.com",
        "https://instagram-account-recovery.secure-access.net",
        "https://twitter-password-reset.verification-process.com",
        "https://ebay-account-confirmation.security-check.xyz",
        "https://yahoo-mail-login.verify-account.net"
    ]
    
    # Create dataset
    data = []
    labels = []
    
    for url in legitimate_urls:
        features = extract_features(url)
        data.append(features)
        labels.append(0)  # 0 for legitimate
    
    for url in phishing_urls:
        features = extract_features(url)
        data.append(features)
        labels.append(1)  # 1 for phishing
    
    return pd.DataFrame(data), pd.Series(labels)

# Function to train the model
def train_model():
    """Train the ML model"""
    with st.spinner("Generating training data and training model..."):
        # Generate training data
        X, y = generate_training_data()
        st.session_state.training_data = X.copy()
        st.session_state.training_data['label'] = y
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Train model
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)
        
        # Evaluate model
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        st.session_state.model = model
        st.session_state.model_trained = True
        st.session_state.accuracy = accuracy
        
        return accuracy, X_test, y_test, y_pred

# Function to predict using trained model
def predict_url(url):
    """Predict if URL is phishing using trained model"""
    if not st.session_state.model_trained:
        return None, None
    
    features = extract_features(url)
    feature_df = pd.DataFrame([features])
    
    # Ensure all required features are present
    expected_features = [
        'url_length', 'num_digits', 'num_letters', 'num_special_chars', 'is_ip',
        'tld_length', 'domain_length', 'subdomain_length', 'has_at_symbol',
        'has_redirect', 'uses_https', 'has_hyphen', 'suspicious_keyword_count',
        'repeat_characters', 'has_mixed_case', 'mixed_case_legitimate_domain',
        'digit_ratio', 'letter_ratio', 'special_char_ratio', 'subdomain_count',
        'multiple_subdomains', 'has_port', 'has_file_extension', 'entropy',
        'is_shortened', 'excessive_special_chars'
    ]
    
    for feature in expected_features:
        if feature not in feature_df.columns:
            feature_df[feature] = 0
    
    # Reorder columns to match training data
    feature_df = feature_df[expected_features]
    
    prediction = st.session_state.model.predict(feature_df)[0]
    probability = st.session_state.model.predict_proba(feature_df)[0]
    
    return prediction, max(probability)

# Function to process uploaded CSV file
def process_uploaded_file(uploaded_file):
    """Process uploaded CSV file for URL analysis"""
    try:
        # Read the CSV file
        df = pd.read_csv(uploaded_file)
        
        # Check if the CSV has a URL column
        url_column = None
        for col in df.columns:
            if 'url' in col.lower():
                url_column = col
                break
        
        if url_column is None:
            st.error("Could not find a URL column in the uploaded file.")
            return None
        
        # Extract features for each URL
        results = []
        for url in df[url_column]:
            if pd.notna(url) and isinstance(url, str):
                if st.session_state.model_trained:
                    prediction, confidence = predict_url(url)
                    status = 'phishing' if prediction == 1 else 'safe'
                else:
                    # Use basic heuristic analysis
                    normalized_url = normalize_url(url)
                    extracted = tldextract.extract(normalized_url)
                    domain = f"{extracted.domain}.{extracted.suffix}"
                    
                    known_legitimate_domains = ['google.com', 'facebook.com', 'microsoft.com', 'apple.com', 
                                               'amazon.com', 'netflix.com', 'github.com', 'twitter.com']
                    
                    has_mixed_case = any(c.islower() and any(d.isupper() for d in url) for c in url)
                    is_mixed_case_legitimate = has_mixed_case and domain in known_legitimate_domains
                    
                    # Determine if phishing
                    is_phishing = any([
                        any(x in url for x in ['login', 'verify', 'account', 'security', 'confirm']),
                        len(url) > 75,
                        any(char.isdigit() and '.' in url for char in url.split('/')[2]),
                        '@' in url,
                        '//' in url[8:],
                        is_mixed_case_legitimate  # Mixed case in known legitimate domain
                    ])
                    
                    status = 'phishing' if is_phishing else 'safe'
                    confidence = 0.85 if is_phishing else 0.75
                
                results.append({
                    'url': url,
                    'status': status,
                    'confidence': confidence
                })
        
        return pd.DataFrame(results)
    except Exception as e:
        st.error(f"Error processing file: {str(e)}")
        return None

# Main app with tabs
tab1, tab2, tab3, tab4 = st.tabs(["🔍 URL Analysis", "🤖 Train Model", "📊 Dataset Info", "📁 CSV Analysis"])

with tab1:
    st.markdown('<h2 class="sub-header">URL Analysis</h2>', unsafe_allow_html=True)
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        url_input = st.text_input("Enter URL to analyze:", placeholder="https://example.com", key="url_input")
    
    with col2:
        st.write("")
        st.write("")
        analyze_btn = st.button("Analyze URL", type="primary")
    
    # Pre-load examples for testing
    example_urls = [
        "https://www.google.com",  # Legitimate
        "https://www.gooGle.com",  # Suspicious (mixed case)
        "https://www.goOglE.com",  # Suspicious (mixed case)
        "https://facebook-security-alert-verify.com",  # Phishing
        "https://apple-id-verification-center.com"  # Phishing
    ]
    
    st.write("Try these examples:")
    cols = st.columns(len(example_urls))
    for i, url in enumerate(example_urls):
        with cols[i]:
            if st.button(f"Ex {i+1}", key=f"ex_{i}"):
                st.session_state.url_input = url

    if analyze_btn and url_input:
        if not url_input.startswith(('http://', 'https://')):
            url_input = 'https://' + url_input
        
        if st.session_state.model_trained:
            # Use ML model for prediction
            with st.spinner("Analyzing URL with ML model..."):
                prediction, confidence = predict_url(url_input)
                
                if prediction is not None:
                    status = 'phishing' if prediction == 1 else 'safe'
                    result = {
                        'status': status,
                        'confidence': confidence,
                        'features': extract_features(url_input)
                    }
                else:
                    st.error("Model not trained. Please train the model first.")
                    st.stop()
        else:
            # Use basic heuristic analysis
            with st.spinner("Analyzing URL with heuristic rules..."):
                # Check for mixed case in legitimate domains (common phishing technique)
                normalized_url = normalize_url(url_input)
                extracted = tldextract.extract(normalized_url)
                domain = f"{extracted.domain}.{extracted.suffix}"
                
                known_legitimate_domains = ['google.com', 'facebook.com', 'microsoft.com', 'apple.com', 
                                           'amazon.com', 'netflix.com', 'github.com', 'twitter.com']
                
                has_mixed_case = any(c.islower() and any(d.isupper() for d in url_input) for c in url_input)
                is_mixed_case_legitimate = has_mixed_case and domain in known_legitimate_domains
                
                # Determine if phishing
                is_phishing = any([
                    any(x in url_input for x in ['login', 'verify', 'account', 'security', 'confirm']),
                    len(url_input) > 75,
                    any(char.isdigit() and '.' in url_input for char in url_input.split('/')[2]),
                    '@' in url_input,
                    '//' in url_input[8:],
                    is_mixed_case_legitimate  # Mixed case in known legitimate domain
                ])
                
                result = {
                    'status': 'phishing' if is_phishing else 'safe',
                    'confidence': 0.85 if is_phishing else 0.75,
                    'features': {
                        'suspicious_keywords': any(x in url_input for x in ['login', 'verify', 'account', 'security', 'confirm']),
                        'long_url': len(url_input) > 75,
                        'uses_https': url_input.startswith('https'),
                        'ip_address': any(char.isdigit() and '.' in url_input for char in url_input.split('/')[2]),
                        'at_symbol': '@' in url_input,
                        'redirects': '//' in url_input[8:],
                        'mixed_case': has_mixed_case,
                        'mixed_case_legitimate': is_mixed_case_legitimate
                    }
                }
        
        # Add to history
        st.session_state.history.append({
            'url': url_input,
            'status': result['status'],
            'confidence': result['confidence'],
            'timestamp': datetime.now()
        })
        
        # Display result
        if result['status'] == 'phishing':
            st.markdown(f"""
            <div class="result-box phishing">
                <h2>🚨 Phishing Detected!</h2>
                <p>This URL has been identified as a potential phishing site with 
                <b>{result['confidence']*100:.1f}% confidence</b>.</p>
            </div>
            """, unsafe_allow_html=True)
            
            st.warning("**Do not enter any personal information on this website.**")
        else:
            st.markdown(f"""
            <div class="result-box safe">
                <h2>✅ URL Appears Safe</h2>
                <p>This URL has been analyzed and appears safe with 
                <b>{result['confidence']*100:.1f}% confidence</b>.</p>
            </div>
            """, unsafe_allow_html=True)
            
            st.info("**Always exercise caution when entering personal information online.**")
        
        # Confidence meter
        st.subheader("Confidence Level")
        confidence_color = "#F44336" if result['status'] == 'phishing' else "#4CAF50"
        st.markdown(f"""
        <div class="confidence-meter">
            <div class="confidence-fill" style="width: {result['confidence']*100}%; background-color: {confidence_color};">
                {result['confidence']*100:.1f}%
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Feature analysis
        st.subheader("Feature Analysis")
        
        if st.session_state.model_trained:
            # Show ML features
            features = result['features']
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**URL Characteristics:**")
                st.write(f"URL Length: {features['url_length']}")
                st.write(f"Number of Digits: {features['num_digits']}")
                st.write(f"Number of Letters: {features['num_letters']}")
                st.write(f"Special Characters: {features['num_special_chars']}")
                st.write(f"Digit Ratio: {features['digit_ratio']:.3f}")
                st.write(f"Letter Ratio: {features['letter_ratio']:.3f}")
                st.write(f"Special Char Ratio: {features['special_char_ratio']:.3f}")
                st.write(f"Entropy: {features['entropy']:.3f}")
                st.write(f"Mixed Case: {'❌ Yes' if features['has_mixed_case'] else '✅ No'}")
                if features['has_mixed_case']:
                    st.write(f"Mixed Case Legitimate Domain: {'❌ Yes' if features['mixed_case_legitimate_domain'] else '✅ No'}")
                
            with col2:
                st.write("**Domain Features:**")
                st.write(f"Uses HTTPS: {'✅ Yes' if features['uses_https'] else '❌ No'}")
                st.write(f"IP Address: {'❌ Yes' if features['is_ip'] else '✅ No'}")
                st.write(f"Has @ Symbol: {'❌ Yes' if features['has_at_symbol'] else '✅ No'}")
                st.write(f"Suspicious Keywords: {features['suspicious_keyword_count']}")
                st.write(f"Subdomain Count: {features['subdomain_count']}")
                st.write(f"Multiple Subdomains: {'❌ Yes' if features['multiple_subdomains'] else '✅ No'}")
                st.write(f"Has Port: {'❌ Yes' if features['has_port'] else '✅ No'}")
                st.write(f"Has File Extension: {'❌ Yes' if features['has_file_extension'] else '✅ No'}")
                st.write(f"Is Shortened: {'❌ Yes' if features['is_shortened'] else '✅ No'}")
                st.write(f"Excessive Special Chars: {'❌ Yes' if features['excessive_special_chars'] else '✅ No'}")
        else:
            # Show basic features
            features = result['features']
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Security Indicators:**")
                if features['uses_https']:
                    st.success("✅ Uses HTTPS encryption")
                else:
                    st.error("❌ Does not use HTTPS")
            
            with col2:
                st.write("**Risk Indicators:**")
                if features['suspicious_keywords']:
                    st.error("❌ Contains suspicious keywords")
                else:
                    st.success("✅ No suspicious keywords")
                    
                if features['long_url']:
                    st.warning("⚠️ Unusually long URL")
                else:
                    st.success("✅ Normal URL length")
                    
                if features['ip_address']:
                    st.error("❌ Uses IP address instead of domain")
                else:
                    st.success("✅ Uses proper domain name")
                    
                if features['at_symbol']:
                    st.error("❌ Contains @ symbol (suspicious)")
                else:
                    st.success("✅ No @ symbol in URL")
                    
                if features['redirects']:
                    st.warning("⚠️ Multiple redirects detected")
                else:
                    st.success("✅ No suspicious redirects")
                    
                if features['mixed_case']:
                    st.warning("⚠️ Mixed case in URL")
                else:
                    st.success("✅ Consistent casing in URL")
                    
                if features['mixed_case_legitimate']:
                    st.error("❌ Mixed case in known legitimate domain (common phishing tactic)")
        
        # Recommendations
        st.subheader("Recommendations")
        if result['status'] == 'phishing':
            st.error("""
            - **Do not** enter any personal information on this website
            - **Do not** download any files from this URL
            - Report this phishing attempt to your organization's security team
            - Consider using a password manager to avoid entering credentials on phishing sites
            """)
        else:
            st.success("""
            - This URL appears safe, but always verify the website identity before entering credentials
            - Look for the lock icon 🔒 in the address bar indicating a secure connection
            - Enable two-factor authentication on your important accounts
            - Keep your browser and security software updated
            """)

with tab2:
    st.markdown('<h2 class="sub-header">Train Machine Learning Model</h2>', unsafe_allow_html=True)
    
    st.markdown("""
    <div class="training-box">
        <h3>🤖 Model Training</h3>
        <p>Train a machine learning model to detect phishing URLs based on various features extracted from URLs.</p>
        <p>The model uses a Random Forest classifier trained on synthetic data that mimics real phishing patterns.</p>
    </div>
    """, unsafe_allow_html=True)
    
    if st.button("Train Model", type="primary"):
        accuracy, X_test, y_test, y_pred = train_model()
        
        st.success(f"✅ Model trained successfully with {accuracy*100:.2f}% accuracy!")
        
        # Show model performance
        st.subheader("Model Performance")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("Accuracy", f"{accuracy*100:.2f}%")
            st.metric("Training Samples", "50")
            st.metric("Features Extracted", "26")
        
        with col2:
            # Confusion matrix
            cm = confusion_matrix(y_test, y_pred)
            fig, ax = plt.subplots(figsize=(6, 4))
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                        xticklabels=['Legitimate', 'Phishing'],
                        yticklabels=['Legitimate', 'Phishing'])
            plt.ylabel('Actual')
            plt.xlabel('Predicted')
            plt.title('Confusion Matrix')
            st.pyplot(fig)
        
        # Feature importance
        st.subheader("Feature Importance")
        if st.session_state.model_trained:
            feature_importance = pd.DataFrame({
                'feature': list(extract_features("https://example.com").keys()),
                'importance': st.session_state.model.feature_importances_
            }).sort_values('importance', ascending=False)
            
            fig = px.bar(feature_importance, x='importance', y='feature', 
                         title='Feature Importance in Phishing Detection',
                         orientation='h')
            st.plotly_chart(fig, use_container_width=True)

with tab3:
    st.markdown('<h2 class="sub-header">Dataset Information</h2>', unsafe_allow_html=True)
    
    st.markdown("""
    <div class="info-box">
        <h3>📊 About the Training Data</h3>
        <p>This demo uses synthetic data that mimics real-world phishing patterns. In a production environment, 
        you would use datasets from sources like:</p>
        <ul>
            <li><b>Kaggle Phishing URL Datasets</b> - Community-contributed datasets with labeled URLs</li>
            <li><b>PhishTank</b> - Community-driven phishing database</li>
            <li><b>OpenPhish</b> - Real-time phishing feed</li>
            <li><b>University Research Datasets</b> - Academic collections of phishing URLs</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
    
    if st.session_state.training_data is not None:
        st.subheader("Training Data Overview")
        st.dataframe(st.session_state.training_data.head(10))
        
        # Data distribution
        st.subheader("Data Distribution")
        fig = px.pie(values=st.session_state.training_data['label'].value_counts().values,
                     names=['Legitimate', 'Phishing'],
                     title='Class Distribution in Training Data')
        st.plotly_chart(fig, use_container_width=True)

with tab4:
    st.markdown('<h2 class="sub-header">CSV File Analysis</h2>', unsafe_allow_html=True)
    
    st.markdown("""
    <div class="info-box">
        <h3>📁 Upload CSV File for Analysis</h3>
        <p>Upload a CSV file containing URLs to analyze them in bulk. The file should have a column containing URLs.</p>
        <p>The system will automatically detect URLs and analyze them for phishing indicators.</p>
    </div>
    """, unsafe_allow_html=True)
    
    uploaded_file = st.file_uploader("Choose a CSV file", type="csv")
    
    if uploaded_file is not None:
        if st.button("Analyze CSV File", type="primary"):
            with st.spinner("Analyzing URLs in the CSV file..."):
                results_df = process_uploaded_file(uploaded_file)
                
                if results_df is not None:
                    st.session_state.uploaded_data = results_df
                    
                    # Display results
                    st.subheader("Analysis Results")
                    st.dataframe(results_df)
                    
                    # Summary statistics - FIXED: Check if 'status' column exists
                    st.subheader("Summary Statistics")
                    col1, col2, col3 = st.columns(3)
                    
                    total_urls = len(results_df)
                    
                    # Check if 'status' column exists before accessing it
                    if 'status' in results_df.columns:
                        phishing_count = len(results_df[results_df['status'] == 'phishing'])
                        safe_count = len(results_df[results_df['status'] == 'safe'])
                    else:
                        # If status column doesn't exist, set default values
                        phishing_count = 0
                        safe_count = total_urls
                    
                    with col1:
                        st.metric("Total URLs", total_urls)
                    with col2:
                        st.metric("Phishing URLs", phishing_count, f"{(phishing_count/total_urls)*100:.1f}%" if total_urls > 0 else "0%")
                    with col3:
                        st.metric("Safe URLs", safe_count, f"{(safe_count/total_urls)*100:.1f}%" if total_urls > 0 else "0%")
                    
                    # Visualization - only if we have status data
                    if 'status' in results_df.columns:
                        st.subheader("Visualization")
                        fig = px.pie(values=[phishing_count, safe_count], 
                                     names=['Phishing', 'Safe'],
                                     title='Distribution of URL Types')
                        st.plotly_chart(fig, use_container_width=True)
                    
                    # Download results
                    csv = results_df.to_csv(index=False)
                    st.download_button(
                        label="Download Results as CSV",
                        data=csv,
                        file_name="phishing_analysis_results.csv",
                        mime="text/csv"
                    )

# History section - FIXED: Check if 'status' key exists in history items
if st.session_state.history:
    st.divider()
    st.subheader("Analysis History")
    
    # Create DataFrame from history, ensuring all items have the required keys
    history_data = []
    for item in st.session_state.history:
        # Make sure each item has the required keys
        safe_item = {
            'url': item.get('url', ''),
            'status': item.get('status', 'unknown'),
            'confidence': item.get('confidence', 0),
            'timestamp': item.get('timestamp', datetime.now())
        }
        history_data.append(safe_item)
    
    history_df = pd.DataFrame(history_data)
    history_df['timestamp'] = pd.to_datetime(history_df['timestamp'])
    history_df = history_df.sort_values(by='timestamp', ascending=False)    
