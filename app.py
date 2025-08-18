import streamlit as st
import numpy as np
import pickle
import re
import requests
import ipaddress
from urllib.parse import urlparse
from requests.exceptions import SSLError, Timeout, RequestException

# --------------------- Utility feature functions ---------------------

def get_domain(url):
    try:
        domain = urlparse(url).netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    except Exception:
        return ""

def having_ip(url):
    try:
        netloc = get_domain(url).split(':')[0]
        ipaddress.ip_address(netloc)
        return 1
    except Exception:
        return 0

def have_at_sign(url):
    return 1 if "@" in url else 0

def get_length(url):
    return 0 if len(url) < 54 else 1

def get_depth(url):
    path = urlparse(url).path
    return sum(1 for seg in path.split("/") if seg)

def redirection(url):
    try:
        pos = url.rfind('//')
        if pos > 6:
            return 1
        return 0
    except Exception:
        return 0

def http_domain(url):
    try:
        parsed = urlparse(url)
        return 1 if parsed.scheme == 'http' else 0
    except Exception:
        return 0

def tiny_url(url):
    shortening_services = (
        r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
        r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
        r"short\.to|budurl\.com|ping\.fm|post\.ly|just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
        r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|db\.tt|"
        r"qr\.ae|adf\.ly|bitly\.com|cur\.lv|tinyurl\.com|bit\.ly|ity\.im|q\.gs|po\.st|bc\.vc|"
        r"twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|prettylinkpro\.com|"
        r"scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|link\.zip\.net"
    )
    return 1 if re.search(shortening_services, url, re.IGNORECASE) else 0

def prefix_suffix(url):
    return 1 if '-' in urlparse(url).netloc else 0

def web_traffic(url):
    return 0  # Placeholder, can integrate API later

def brand_name_check(url):
    suspicious_brands = ["paypal", "bankofamerica", "appleid", "netflix", "amazon", "facebook", "microsoft"]
    domain = get_domain(url)
    return 1 if any(brand in domain.lower() for brand in suspicious_brands) else 0

# --------------------- HTML / JS features ---------------------

def get_http_response(url, timeout=5):
    try:
        headers = {"User-Agent": "Mozilla/5.0 (compatible; PhishDetector/1.0)"}
        return requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
    except (SSLError, Timeout, RequestException):
        return None

def contains_iframe(response):
    if not response:
        return 1
    return 0 if re.search(r"<\s*iframe|<\s*frame", response.text, re.IGNORECASE) else 1

def mouse_over(response):
    if not response:
        return 1
    return 1 if re.search(r"onmouseover", response.text, re.IGNORECASE) else 0

def right_click(response):
    if not response:
        return 1
    if re.search(r"event\.button\s*==\s*2", response.text, re.IGNORECASE):
        return 0
    if re.search(r"addEventListener\(['\"]contextmenu['\"]", response.text, re.IGNORECASE):
        return 0
    return 1

def forwarding(response):
    if not response:
        return 1
    return 0 if len(response.history) <= 2 else 1

# --------------------- Feature extraction ---------------------

def extract_features(url):
    features = []
    features.append(having_ip(url))
    features.append(have_at_sign(url))
    features.append(get_length(url))
    features.append(get_depth(url))
    features.append(redirection(url))
    features.append(http_domain(url))
    features.append(tiny_url(url))
    features.append(prefix_suffix(url))
    features.append(0)  # dns
    features.append(0)  # dns_age
    features.append(0)  # dns_end
    features.append(web_traffic(url))
    features.append(brand_name_check(url))  # NEW feature: brand name
    response = get_http_response(url)
    features.append(contains_iframe(response))
    features.append(mouse_over(response))
    features.append(right_click(response))
    features.append(forwarding(response))
    return features

# --------------------- Prediction ---------------------

def predict_phishing(features, model_path="mlp_model.pkl"):
    new_data = np.array([features])
    try:
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
            pred = model.predict(new_data)
            return int(pred[0]), "ML model used"
    except:
        score = 0
        score += features[0]  # IP in URL
        score += features[1]  # @ sign
        score += features[5]  # HTTP
        score += features[6]  # tiny URL
        score += features[7]  # prefix-suffix
        score += features[12] # brand name
        score += (1 - features[13])  # iframe presence
        score += (1 - features[15])  # right-click disabled

        # Lower threshold — even one strong signal can flag phishing
        if score >= 1:
            return 0, f"Heuristic: suspicious score {score}"
        else:
            return 1, f"Heuristic: score {score}"

# --------------------- Streamlit UI ---------------------

def main():
    st.title("Phishing URL Detector — Enhanced")
    st.write("Paste a URL to check for phishing indicators.")

    url = st.text_input("Enter URL:", "")
    if st.button("Check URL"):
        if not url:
            st.error("Please enter a URL.")
            return
        st.info("Extracting features...")
        features = extract_features(url)
        st.write("Features vector:", features)
        label, detail = predict_phishing(features)
        if label == 0:
            st.error(f"Phishing Alert! ({detail})")
        else:
            st.success(f"No phishing detected. ({detail})")

if __name__ == "__main__":
    main()
