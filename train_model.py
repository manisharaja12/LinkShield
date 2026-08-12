"""
Model Training Script
Trains a RandomForest classifier to detect malicious URLs
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

from feature_extractor import URLFeatureExtractor
from dataset_loader import DatasetLoader

class URLModelTrainer:
    """Train and evaluate URL classification model"""
    
    def __init__(self):
        self.feature_extractor = URLFeatureExtractor()
        self.model = None
        self.feature_names = self.feature_extractor.get_feature_names()
        self.model_path = 'url_classifier_model.pkl'
    
    def prepare_data(self, df):
        """
        Extract features from URLs in the dataset
        Returns X (features) and y (labels)
        """
        print("\n📊 Extracting features from URLs...")
        
        # Extract features for each URL
        features_list = []
        for idx, url in enumerate(df['url']):
            if idx % 100 == 0:
                print(f"  Processed {idx}/{len(df)} URLs...", end='\r')
            
            features = self.feature_extractor.extract_features(url)
            features_list.append(features)
        
        print(f"  Processed {len(df)}/{len(df)} URLs... Done!")
        
        # Convert to DataFrame
        X = pd.DataFrame(features_list)
        
        # Convert labels to binary (0 = legitimate, 1 = malicious)
        y = (df['label'] == 'malicious').astype(int)
        
        print(f"✓ Feature extraction complete")
        print(f"  Features: {X.shape[1]}")
        print(f"  Samples: {X.shape[0]}")
        
        return X, y
    
    def train(self, X, y):
        """
        Train RandomForest classifier
        """
        print("\n🎯 Splitting data into train/test sets...")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"  Training set: {len(X_train)} samples")
        print(f"  Test set: {len(X_test)} samples")
        
        print("\n🌲 Training RandomForest classifier...")
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=10,
            min_samples_leaf=5,
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_train, y_train)
        print("✓ Model training complete!")
        
        # Evaluate on test set
        print("\n📈 Evaluating model performance...")
        y_pred = self.model.predict(X_test)
        
        accuracy = accuracy_score(y_test, y_pred)
        print(f"\n🎯 Accuracy: {accuracy:.2%}")
        
        print("\n📊 Classification Report:")
        print(classification_report(y_test, y_pred, 
                                   target_names=['Legitimate', 'Malicious']))
        
        print("\n🔢 Confusion Matrix:")
        cm = confusion_matrix(y_test, y_pred)
        print(cm)
        
        # Plot confusion matrix
        self._plot_confusion_matrix(cm, y_test, y_pred)
        
        # Plot feature importance
        self._plot_feature_importance()
        
        return accuracy
    
    def _plot_confusion_matrix(self, cm, y_test, y_pred):
        """Plot confusion matrix"""
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                   xticklabels=['Legitimate', 'Malicious'],
                   yticklabels=['Legitimate', 'Malicious'])
        plt.title('Confusion Matrix')
        plt.ylabel('Actual')
        plt.xlabel('Predicted')
        plt.tight_layout()
        plt.savefig('confusion_matrix.png', dpi=150, bbox_inches='tight')
        print("✓ Confusion matrix saved: confusion_matrix.png")
        plt.close()
    
    def _plot_feature_importance(self):
        """Plot feature importance"""
        if self.model is None:
            return
        
        # Get feature importances
        importances = self.model.feature_importances_
        indices = np.argsort(importances)[::-1]
        
        # Plot top 15 features
        plt.figure(figsize=(12, 8))
        top_n = min(15, len(self.feature_names))
        
        plt.barh(range(top_n), importances[indices[:top_n]][::-1])
        plt.yticks(range(top_n), [self.feature_names[i] for i in indices[:top_n]][::-1])
        plt.xlabel('Feature Importance')
        plt.title('Top Feature Importances for URL Classification')
        plt.tight_layout()
        plt.savefig('feature_importance.png', dpi=150, bbox_inches='tight')
        print("✓ Feature importance plot saved: feature_importance.png")
        plt.close()
    
    def save_model(self):
        """Save trained model to disk"""
        if self.model is None:
            print("⚠️  No model to save!")
            return
        
        joblib.dump(self.model, self.model_path)
        print(f"✓ Model saved: {self.model_path}")
    
    def load_model(self):
        """Load trained model from disk"""
        try:
            self.model = joblib.load(self.model_path)
            print(f"✓ Model loaded: {self.model_path}")
            return True
        except FileNotFoundError:
            print(f"⚠️  Model file not found: {self.model_path}")
            return False

def main():
    """Main training pipeline"""
    print("="*60)
    print("🔒 SUSPICIOUS URL DETECTOR - MODEL TRAINING")
    print("="*60)
    
    # Load dataset
    loader = DatasetLoader()
    df = loader.load_dataset()
    
    # Initialize trainer
    trainer = URLModelTrainer()
    
    # Prepare data
    X, y = trainer.prepare_data(df)
    
    # Train model
    accuracy = trainer.train(X, y)
    
    # Save model
    trainer.save_model()
    
    print("\n" + "="*60)
    print("✅ TRAINING COMPLETE!")
    print(f"   Final Accuracy: {accuracy:.2%}")
    print("="*60)
    print("\nYou can now use the model for predictions!")
    print("Run: python main.py")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
