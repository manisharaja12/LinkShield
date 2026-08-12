"""
URL Prediction Engine
Loads trained model and predicts if URLs are suspicious or safe
"""

import joblib
import pandas as pd
import numpy as np
from feature_extractor import URLFeatureExtractor

class URLPredictor:
    """Predict if URLs are malicious or legitimate"""
    
    def __init__(self, model_path='url_classifier_model.pkl'):
        self.model_path = model_path
        self.feature_extractor = URLFeatureExtractor()
        self.model = None
        self.load_model()
    
    def load_model(self):
        """Load the trained model"""
        try:
            self.model = joblib.load(self.model_path)
            return True
        except FileNotFoundError:
            print(f"❌ Error: Model file not found: {self.model_path}")
            print("Please train the model first by running: python train_model.py")
            return False
    
    def predict(self, url):
        """
        Predict if a URL is malicious or legitimate
        Returns: prediction (0=safe, 1=malicious), probability, explanation
        """
        if self.model is None:
            return None, None, ["Model not loaded"]
        
        # Extract features
        features = self.feature_extractor.extract_features(url)
        
        # Convert to DataFrame with correct feature order
        feature_names = self.feature_extractor.get_feature_names()
        X = pd.DataFrame([features])
        X.columns = feature_names
        
        # Make prediction
        prediction = self.model.predict(X)[0]
        probability = self.model.predict_proba(X)[0]
        
        # Get explanation
        explanation = self.feature_extractor.explain_features(features)
        
        return prediction, probability, explanation, features
    
    def analyze_url(self, url):
        """
        Analyze a URL and return detailed results
        """
        print("\n" + "="*60)
        print("🔍 ANALYZING URL")
        print("="*60)
        print(f"URL: {url}")
        print("-"*60)
        
        # Get prediction
        result = self.predict(url)
        
        if result[0] is None:
            print("❌ Analysis failed - model not loaded")
            return
        
        prediction, probability, explanation, features = result
        
        # Display result
        if prediction == 1:
            print("\n🚨 VERDICT: SUSPICIOUS/MALICIOUS")
            print(f"   Confidence: {probability[1]:.1%}")
        else:
            print("\n✅ VERDICT: SAFE/LEGITIMATE")
            print(f"   Confidence: {probability[0]:.1%}")
        
        # Display explanation
        if explanation:
            print("\n📋 REASONS:")
            for reason in explanation:
                print(f"   {reason}")
        else:
            if prediction == 0:
                print("\n✓ No suspicious patterns detected")
                print("✓ URL appears to follow normal conventions")
        
        # Display key features
        print("\n📊 KEY FEATURES:")
        print(f"   • URL Length: {features['url_length']} characters")
        print(f"   • HTTPS: {'Yes ✓' if features['has_https'] else 'No ✗'}")
        print(f"   • IP Address: {'Yes ⚠️' if features['has_ip'] else 'No ✓'}")
        print(f"   • Suspicious Keywords: {features['num_suspicious_keywords']}")
        print(f"   • Number of Dots: {features['num_dots']}")
        print(f"   • Number of Hyphens: {features['num_hyphens']}")
        
        print("="*60 + "\n")
        
        return prediction, probability

def main():
    """Test the predictor with example URLs"""
    predictor = URLPredictor()
    
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "http://paypal-verify.com/update-account.php",
        "https://github.com/user/repo",
        "http://192.168.1.1/admin/login.php"
    ]
    
    for url in test_urls:
        predictor.analyze_url(url)
        input("Press Enter to continue...")

if __name__ == "__main__":
    main()
