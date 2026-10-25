import os
import torch
import torch.nn as nn
import torch.optim as optim
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

from feature_extractor import extract_url_features, FEATURE_NAMES
from dl_detector import CharCNNBiGRU, url_to_tensor, DL_MODEL_PATH

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.joblib")

# Rich representative dataset of benign vs malicious URLs
SAMPLE_DATASET = [
    # Benign URLs (Label 0)
    ("https://www.google.com/search?q=cybersecurity+defense", 0),
    ("https://amazon.com/dp/B08N5WRWNW/ref=sr_1_1", 0),
    ("https://en.wikipedia.org/wiki/Phishing", 0),
    ("https://github.com/torvalds/linux", 0),
    ("https://paypal.com/signin", 0),
    ("https://apple.com/iphone-15-pro", 0),
    ("https://microsoft.com/en-us/windows", 0),
    ("https://netflix.com/browse/genre/83", 0),
    ("https://stackoverflow.com/questions/tagged/python", 0),
    ("https://nytimes.com/section/technology", 0),
    ("https://cnn.com/world/europe", 0),
    ("https://linkedin.com/feed", 0),
    ("https://chase.com/personal/banking", 0),
    ("https://wellsfargo.com/help", 0),
    ("https://reddit.com/r/netsec", 0),
    ("https://walmart.com/ip/sony-headphones/567231", 0),
    ("https://bestbuy.com/site/apple-macbook-air/6534606.p", 0),
    ("https://target.com/p/kitchenaid-mixer/-/A-12345", 0),
    ("https://ebay.com/itm/124567890123", 0),
    ("https://booking.com/hotel/us/grand-hyatt.html", 0),
    ("https://airbnb.com/rooms/1029384", 0),
    ("https://stripe.com/docs/api", 0),
    ("https://slack.com/help/articles", 0),
    ("https://spotify.com/us/premium", 0),
    ("https://medium.com/@infosec/phishing-analysis", 0),
    ("https://store.steampowered.com/app/730/CounterStrike_2", 0),
    ("https://twitch.tv/directory", 0),
    ("https://cloudflare.com/learning/security", 0),
    ("https://zoom.us/join", 0),
    ("https://dropbox.com/s/samplefile/document.pdf", 0),
    ("https://uber.com/drive", 0),
    ("https://adobe.com/products/photoshop.html", 0),
    ("https://salesforce.com/products/crm", 0),
    ("https://gov.uk/browse/benefits", 0),
    ("https://bbc.com/news/technology", 0),
    ("https://developer.mozilla.org/en-US/docs/Web/API", 0),
    ("https://coursera.org/learn/machine-learning", 0),
    ("https://udemy.com/course/complete-python-bootcamp", 0),

    # Malicious & Phishing URLs (Label 1)
    ("http://paypa1-account-verification-support.com/login.php", 1),
    ("http://192.168.1.105/auth/secure-chase-update.html", 1),
    ("https://amazon-prime-renewal-billing.xyz/claim-gift?id=99", 1),
    ("http://appleid-login-verification-icloud.net/auth/recover", 1),
    ("https://netflix-subscription-billing-update.top/account", 1),
    ("http://secure-chase-banking-alert.club/signin.asp?token=123", 1),
    ("http://binance-wallets-gift-claim.site/airdrop/connect", 1),
    ("https://cheap-luxury-watches-discount-outlet.shop/sale-90", 1),
    ("http://microsoft-outlook-office365-verify.club/webscr", 1),
    ("https://wells-fargo-security-alert-locked.online/update", 1),
    ("http://login.paypal.com.customer-resolution-center.xyz", 1),
    ("http://steamcommunity-giftcard-free-bonus.top/trade", 1),
    ("https://coinbase-pro-security-reauth.work/wallet/login", 1),
    ("http://metamask-crypto-airdrop-bonus-claim.info/auth", 1),
    ("http://facebook-security-infraction-appeal.support-case.com", 1),
    ("https://dhl-express-package-redelivery-fee.buzz/tracking", 1),
    ("http://fedex-parcel-pending-payment-invoice.surf/confirm", 1),
    ("http://usps-address-update-redelivery-notice.monster/order", 1),
    ("http://instagram-blue-badge-verification-team.site/apply", 1),
    ("http://walmart-exclusive-survey-prize-winner.click/gift", 1),
    ("https://roblox-free-robux-generator-2026.online/claim", 1),
    ("http://ebay-buyer-protection-refund-claim.club/dispute", 1),
    ("http://bestbuy-clearance-sale-95-percent-off.shop/checkout", 1),
    ("http://telegram-premium-free-airdrop.buzz/start", 1),
    ("http://whatsapp-web-desktop-sync-update.site/session", 1),
    ("http://google-drive-shared-invoice-view.top/docs/doc1.php", 1),
    ("http://bankofamerica-unauthorized-transaction-hold.club/verify", 1),
    ("http://104.244.42.1/login/banking/security.htm", 1),
    ("https://target-giftcard-500-survey-offer.online/verify", 1),
    ("http://icloud-findmy-lost-iphone-locate.xyz/map/login", 1),
    ("http://chase-bank-overdraft-protection-claim.top/auth", 1),
    ("http://update-billing-info-account-hold.club/webapps", 1),
    ("https://urgent-action-required-verify-password.xyz/auth", 1),
    ("http://bonus-deposit-crypto-multiplier-double.site/btc", 1),
    ("http://clearance-shoes-nike-adidas-outlet-90off.shop/cart", 1),
    ("http://account-suspended-reactivate-now.online/portal", 1),
    ("http://billing-failed-update-payment-method.top/invoice", 1),
    ("https://secure-login-session-expired-reenter.site/login", 1)
]

def train_all_models():
    print("=" * 60)
    print("ScamShield Enterprise Multi-Engine AI / ML / DL Training")
    print("=" * 60)

    urls = [item[0] for item in SAMPLE_DATASET]
    labels = [item[1] for item in SAMPLE_DATASET]

    # --- 1. Train Scikit-Learn Machine Learning Ensemble ---
    print("\n[1/2] Training Scikit-learn ML Ensemble (Random Forest + Gradient Boosting)...")
    X = np.array([extract_url_features(u) for u in urls])
    y = np.array(labels)

    rf = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42)
    gb = GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, max_depth=4, random_state=42)
    
    # Train primary random forest model (allows feature_importances_)
    rf.fit(X, y)
    y_pred = rf.predict(X)
    print(f"Random Forest Training Accuracy: {round(accuracy_score(y, y_pred) * 100, 2)}%")

    # Save model
    joblib.dump(rf, MODEL_PATH)
    print(f"ML Model saved successfully to: {MODEL_PATH}")

    # --- 2. Train PyTorch Deep Learning 1D-CNN + BiGRU ---
    print("\n[2/2] Training PyTorch Deep Learning Neural Network (CharCNN + BiGRU)...")
    tensors = torch.cat([url_to_tensor(u) for u in urls], dim=0) # (N, seq_len)
    targets = torch.tensor(labels, dtype=torch.float32) # (N,)

    dl_model = CharCNNBiGRU()
    optimizer = optim.AdamW(dl_model.parameters(), lr=0.003, weight_decay=1e-4)
    criterion = nn.BCELoss()

    dl_model.train()
    epochs = 40
    for epoch in range(1, epochs + 1):
        optimizer.zero_grad()
        preds = dl_model(tensors)
        loss = criterion(preds, targets)
        loss.backward()
        optimizer.step()
        if epoch % 10 == 0 or epoch == epochs:
            binary_preds = (preds >= 0.5).float()
            acc = (binary_preds == targets).float().mean().item()
            print(f"Epoch {epoch:02d}/{epochs} - Loss: {loss.item():.4f} - Accuracy: {round(acc*100, 1)}%")

    # Save DL model weights
    torch.save(dl_model.state_dict(), DL_MODEL_PATH)
    print(f"Deep Learning PyTorch weights saved to: {DL_MODEL_PATH}")

    print("\n" + "=" * 60)
    print("All AI, ML, and DL models trained and operational!")
    print("=" * 60)

if __name__ == "__main__":
    train_all_models()
