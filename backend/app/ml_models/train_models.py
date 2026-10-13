import os
import json
import joblib
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, precision_score, recall_score, f1_score

# Directory paths
MODELS_DIR = Path(__file__).resolve().parent
DATA_DIR = MODELS_DIR.parent.parent.parent / "data"

# Comprehensive Curated Phishing & Ham dataset (SMS, Email, Scams, Legitimate alerts)
DATASET = [
    # --- PHISHING / SCAM SAMPLES (Label: 1) ---
    ("URGENT: Your SBI bank account has been blocked due to pending KYC. Click http://sbi-kyc-update.xyz to verify immediately.", 1),
    ("Dear customer, your electricity power will be disconnected tonight at 9:30 PM. Call our electricity officer at 9876543210 immediately.", 1),
    ("Congratulations! You have won a cash prize of Rs 50,000 from Flipkart Lucky Draw. Claim your reward now at http://reward-flipkart-win.top", 1),
    ("Dear User, your Netflix subscription expired. Update your credit card details within 24 hours at http://netflix-billing-renew.cc to avoid account termination.", 1),
    ("ALERT: Unauthorized transaction of $950.00 detected on your Chase account. If not you, verify OTP at http://chase-security-alert.click immediately.", 1),
    ("Income Tax Refund of Rs 15,490 approved. Please submit your bank account details and PAN at http://incometax-refund-gov.xyz", 1),
    ("Your package cannot be delivered due to incomplete address. Please pay $1.99 redelivery fee at http://fedex-parcel-redelivery.monster", 1),
    ("Dear Axis Bank customer, your debit card is blocked. Send your 16 digit card number, CVV and OTP to reactivate instantly.", 1),
    ("Hurry! Free iPhone 15 Pro Max giveaway for the first 100 users. Enter your phone number and claim at http://apple-promo-win.buzz", 1),
    ("Your PayPal account has been limited due to suspicious activity. Log in at http://paypal-resolution-center.xyz to restore access.", 1),
    ("Your WhatsApp account will be deleted within 12 hours. Click here to confirm your identity with verification code.", 1),
    ("Urgent: Amazon security notice. Unusual sign-in attempt from Russia. Change password immediately at http://amazon-security-auth.top", 1),
    ("Job Offer: Earn Rs 5,000 to 10,000 daily working 2 hours from home by liking YouTube videos. Contact on Telegram: @quick_cash_india", 1),
    ("Final reminder: Your SIM card will be deactivated due to non-verification. Dial *121*5# or click link to complete biometric KYC.", 1),
    ("Dear customer, your Paytm wallet is suspended. Complete your video KYC now at http://paytm-kyc-online.info to unfreeze balance.", 1),
    ("Your Crypto wallet Metamask needs synchronization. Connect your secret recovery seed phrase at http://metamask-sync-wallet.xyz", 1),
    ("ALERT: Income tax department has issued a warrant against your PAN. Call officer immediately to settle penalty.", 1),
    ("Your HDFC credit card reward points worth Rs 8,500 will expire today. Redeem cash directly to bank at http://hdfc-points-claim.top", 1),
    ("Google Security Alert: Someone knows your password. Confirm credentials at http://google-account-verify.online immediately.", 1),
    ("Action Required: Your Facebook page violates copyright terms and will be disabled permanently. Appeal at http://meta-support-appeal.cf", 1),

    # --- BENIGN / LEGITIMATE SAMPLES (Label: 0) ---
    ("Hey, are we still meeting for lunch at 1 PM today? Let me know.", 0),
    ("Your OTP for Swiggy food order delivery is 482910. Do not share this OTP with anyone.", 0),
    ("Your flight 6E-204 from Delhi to Mumbai is on schedule. Web check-in is now open on the official IndiGo app.", 0),
    ("Your monthly electricity bill of Rs 1,420 for consumer number 98213 is generated. Due date is 20th Oct. Pay via official app or portal.", 0),
    ("Hi Rahul, please find attached the meeting minutes and project timeline discussed during today's college capstone review.", 0),
    ("Your Amazon order #402-981293 has been dispatched and will arrive by tomorrow evening.", 0),
    ("Dear customer, Rs 500.00 credited to your HDFC bank account via UPI from Rohan on 07-Oct-2026. Ref: 4892109823.", 0),
    ("Reminder: College team presentation for CyberShield is scheduled tomorrow at 10:00 AM in Lab 3.", 0),
    ("Your Uber ride with driver Ramesh (Swift Dzire DL01AB1234) has arrived at your pickup location.", 0),
    ("Hey buddy, can you share the lecture notes for chapter 4 of Data Analysis?", 0),
    ("Thank you for paying your Airtel postpaid bill of Rs 499. Payment received successfully.", 0),
    ("Your appointment with Dr. Sharma is confirmed for Thursday at 4:30 PM. Please arrive 10 minutes early.", 0),
    ("GitHub: A new security advisory has been published for one of your dependencies.", 0),
    ("Happy Birthday! Wishing you a fantastic year ahead filled with happiness and success.", 0),
    ("Your library book 'Computer Networks by Tanenbaum' is due for return on 15th Oct.", 0),
    ("Google Verification Code: 918234. Use this to verify your Google Account.", 0),
    ("Good morning team, please review the pull request on GitHub before our standup meeting.", 0),
    ("Your package from Flipkart has been delivered. We hope you liked the shopping experience.", 0),
    ("Class cancellation notice: Today's 2 PM physics lecture is rescheduled to Friday.", 0),
    ("Your recharge of Rs 299 for Jio number 9811223344 is successful. Validity 28 days with 1.5GB/day data.", 0)
]

def train_and_save_model():
    texts, labels = zip(*DATASET)
    X_train, X_test, y_train, y_test = train_test_split(texts, labels, test_size=0.25, random_state=42, stratify=labels)

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), lowercase=True, stop_words="english")),
        ("clf", LogisticRegression(random_state=42))
    ])

    pipeline.fit(X_train, y_train)

    # Evaluate
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    cm = confusion_matrix(y_test, y_pred).tolist()

    report = classification_report(y_test, y_pred, output_dict=True)

    metrics = {
        "model_name": "TF-IDF + Logistic Regression Phishing Classifier",
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "confusion_matrix": cm,
        "classification_report": report,
        "training_samples": len(X_train),
        "test_samples": len(X_test)
    }

    # Save model
    model_path = MODELS_DIR / "phishing_classifier.joblib"
    joblib.dump(pipeline, model_path)

    # Save metrics JSON for the analytics dashboard
    metrics_path = MODELS_DIR / "model_metrics.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print(f"Model successfully saved to {model_path}")
    print(f"Metrics saved to {metrics_path}")
    print(f"Precision: {prec:.2f}, Recall: {rec:.2f}, F1-Score: {f1:.2f}")

if __name__ == "__main__":
    train_and_save_model()
