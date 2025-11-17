# 🛡️ PHISHING WEBSITE DETECTION USING XGBoost and Random Forest

Phishing is one of the most widespread cyberattacks globally, causing financial loss, identity theft, data breaches, and compromised systems.  
This project implements a **Machine Learning-based phishing website detection system** using **XGBoost** and **Random Forest**, leveraging URL feature analysis to classify websites as *Legitimate (0)* or *Phishing (1)*.

---

## 🚨 Why This Project?

- Over **3.4 billion spam emails** are sent daily worldwide.  
- In **2021**, more than **323,972 users** became victims of phishing.  
- Average loss per phishing attack: **$136**  
- Total losses exceeded **$44.2 million** in a single year.  

Traditional heuristic or rule-based methods struggle to keep up with rapidly evolving phishing techniques.  
This ML solution improves detection accuracy, automation, and real-time classification.

---

# 📌 Problem Statement

The rapid increase in online transactions and digital communication has resulted in the rise of phishing attacks.  
Traditional detection techniques fail because phishing websites:

- Look almost identical to legitimate sites  
- Use deceptive domain names  
- Change dynamically  
- Exploit human vulnerability  

The goal of this project is to build a robust ML model using **XGBoost** and **Random Forest**, capable of identifying phishing URLs with high accuracy.

---

# 🔍 Introduction

Phishing attacks mimic real websites to trick users into revealing personal or financial information.  
This project:

- Extracts features from URLs  
- Applies data preprocessing  
- Trains multiple ML models  
- Evaluates performance  
- Selects the best model (XGBoost + RFM)  
- Exports final classifier for deployment  

The final system can be integrated into browser extensions, security tools, or streamlit apps.

---

# 🚀 Approach

### ✔ 1. Dataset Collection

| Type | Source | Count |
|------|--------|--------|
| Phishing URLs | PhishTank | 5,000 |
| Legitimate URLs | UNB Dataset | 5,000 |

Total: **10,000 URLs**

---

### ✔ 2. Feature Extraction

A total of **17 URL features** were extracted:

- **Address bar-based features** (9)
- **Domain-based features** (4)
- **HTML & JavaScript-based features** (4)

Stored in:  
`Data Files/5.urldata.csv`

---

### ✔ 3. Data Preprocessing

- Cleaned missing values  
- Standardized/encoded features  
- 80/20 train–test split  
  - Training → 8,000 samples  
  - Testing → 2,000 samples  
- Classification labels:
  - **1 → Phishing**
  - **0 → Legitimate**

---

### ✔ 4. Machine Learning Models Used

- Decision Tree  
- Random Forest  
- Multilayer Perceptron (MLP)  
- XGBoost  
- SVM  
- Autoencoder Neural Network  

---

# 📊 Model Performance Summary

### **Overall Training & Testing Accuracy**

| Model | Train Accuracy | Test Accuracy |
|-------|----------------|----------------|
| Decision Tree | 0.812 | 0.820 |
| Random Forest | 0.819 | 0.824 |
| Multilayer Perceptrons | 0.865 | 0.858 |
| **XGBoost** | **0.867** | **0.858** |
| Autoencoder | 0.002 | 0.001 |
| SVM | 0.800 | 0.806 |

---

# 🧪 Detailed Evaluation Metrics

## **1️⃣ Random Forest Performance**

| Dataset | Accuracy | Recall | F1 Score | Precision |
|---------|----------|--------|----------|------------|
| Dataset 1 | 0.824 | 0.958 | 0.957 | 0.958 |
| Dataset 2 | 0.867 | 0.799 | 0.857 | 0.924 |
| Dataset 3 | 0.867 | 0.799 | 0.861 | 0.924 |

---

## **2️⃣ XGBoost Performance**

| Dataset | Accuracy | Recall | F1 Score | Precision |
|---------|----------|--------|----------|------------|
| Dataset 1 | 0.858 | 0.948 | 0.947 | 0.950 |
| Dataset 2 | 0.870 | 0.808 | 0.861 | 0.923 |
| Dataset 3 | 0.870 | 0.808 | 0.861 | 0.923 |

---

# 🎯 Training & Testing Results

XGBoost was trained for **50 epochs**, producing:

- **Training Accuracy:** 86.7%  
- **Testing Accuracy:** 85.8%  

Thus, **XGBoost + RFM** emerged as the best model.

---

# 🏆 Final Result

### ✔ Best-performing model: **XGBoost**  
### ✔ Final accuracy: **86.7%**  
### ✔ Model exported as:

