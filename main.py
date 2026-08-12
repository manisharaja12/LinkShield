"""
Suspicious Link Analyzer - Main CLI Interface
Interactive command-line tool for analyzing URLs
"""

import sys
import os
from predict import URLPredictor
from train_model import URLModelTrainer
from dataset_loader import DatasetLoader

def print_banner():
    """Print application banner"""
    print("\n" + "="*60)
    print("🔒 SUSPICIOUS LINK ANALYZER")
    print("   Machine Learning-Based URL Security Scanner")
    print("="*60 + "\n")

def print_menu():
    """Print main menu"""
    print("\n📋 MENU:")
    print("  1. Analyze a single URL")
    print("  2. Analyze multiple URLs")
    print("  3. Train/Retrain model")
    print("  4. View model information")
    print("  5. Exit")
    print("-"*60)

def analyze_single_url(predictor):
    """Analyze a single URL"""
    print("\n" + "-"*60)
    url = input("🔗 Enter URL to analyze: ").strip()
    
    if not url:
        print("⚠️  No URL provided!")
        return
    
    # Add http:// if no protocol specified
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        print(f"   (Added http:// prefix: {url})")
    
    predictor.analyze_url(url)

def analyze_multiple_urls(predictor):
    """Analyze multiple URLs"""
    print("\n" + "-"*60)
    print("Enter URLs one per line. Type 'done' when finished:")
    print("-"*60)
    
    urls = []
    while True:
        url = input("🔗 URL: ").strip()
        if url.lower() == 'done':
            break
        if url:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            urls.append(url)
    
    if not urls:
        print("⚠️  No URLs provided!")
        return
    
    print(f"\n📊 Analyzing {len(urls)} URLs...\n")
    
    results = {'safe': 0, 'suspicious': 0}
    
    for i, url in enumerate(urls, 1):
        print(f"\n[{i}/{len(urls)}] {url}")
        prediction, probability = predictor.analyze_url(url)
        
        if prediction == 1:
            results['suspicious'] += 1
        else:
            results['safe'] += 1
    
    # Summary
    print("\n" + "="*60)
    print("📊 BATCH ANALYSIS SUMMARY")
    print("="*60)
    print(f"   Total URLs analyzed: {len(urls)}")
    print(f"   ✅ Safe: {results['safe']}")
    print(f"   🚨 Suspicious: {results['suspicious']}")
    print("="*60 + "\n")

def train_model():
    """Train or retrain the model"""
    print("\n" + "="*60)
    print("🎯 MODEL TRAINING")
    print("="*60)
    print("\nThis will train a new model using the dataset.")
    print("If you haven't downloaded the full Kaggle dataset,")
    print("a sample dataset will be created automatically.")
    print("")
    
    response = input("Continue with training? (yes/no): ").strip().lower()
    
    if response not in ['yes', 'y']:
        print("Training cancelled.")
        return
    
    # Load dataset
    loader = DatasetLoader()
    df = loader.load_dataset()
    
    # Train model
    trainer = URLModelTrainer()
    X, y = trainer.prepare_data(df)
    accuracy = trainer.train(X, y)
    trainer.save_model()
    
    print("\n✅ Training complete!")
    print(f"   Model saved and ready to use.")
    input("\nPress Enter to continue...")

def view_model_info():
    """Display model information"""
    print("\n" + "="*60)
    print("ℹ️  MODEL INFORMATION")
    print("="*60)
    
    model_path = 'url_classifier_model.pkl'
    
    if not os.path.exists(model_path):
        print("\n❌ No trained model found!")
        print("   Please train the model first (Option 3)")
    else:
        # Get file size
        size_bytes = os.path.getsize(model_path)
        size_mb = size_bytes / (1024 * 1024)
        
        print(f"\n✓ Model Status: Trained and Ready")
        print(f"✓ Model File: {model_path}")
        print(f"✓ Model Size: {size_mb:.2f} MB")
        print(f"\n📊 Model Type: RandomForest Classifier")
        print(f"📊 Features: 21 URL characteristics")
        print(f"📊 Training Algorithm: Ensemble Learning")
        
        print("\n📋 Analyzed Features:")
        features = [
            "URL length", "Number of dots", "HTTPS presence",
            "IP address detection", "Suspicious keywords",
            "Special characters", "Domain structure",
            "Subdomain patterns", "Digit ratios", "and more..."
        ]
        for feature in features:
            print(f"   • {feature}")
        
        # Check for visualization files
        if os.path.exists('confusion_matrix.png'):
            print(f"\n📈 Visualization: confusion_matrix.png")
        if os.path.exists('feature_importance.png'):
            print(f"📈 Visualization: feature_importance.png")
    
    print("="*60)
    input("\nPress Enter to continue...")

def main():
    """Main application loop"""
    print_banner()
    
    # Check if model exists
    model_path = 'url_classifier_model.pkl'
    if not os.path.exists(model_path):
        print("⚠️  No trained model found!")
        print("   Training a new model with sample data...")
        print("")
        
        # Auto-train with sample data
        loader = DatasetLoader()
        df = loader.load_dataset()
        
        trainer = URLModelTrainer()
        X, y = trainer.prepare_data(df)
        trainer.train(X, y)
        trainer.save_model()
        
        print("\n✅ Model training complete!")
        input("Press Enter to continue...")
    
    # Initialize predictor
    predictor = URLPredictor()
    
    # Main loop
    while True:
        print_menu()
        choice = input("Select an option (1-5): ").strip()
        
        if choice == '1':
            analyze_single_url(predictor)
        elif choice == '2':
            analyze_multiple_urls(predictor)
        elif choice == '3':
            train_model()
            # Reload predictor with new model
            predictor = URLPredictor()
        elif choice == '4':
            view_model_info()
        elif choice == '5':
            print("\n👋 Thank you for using Suspicious Link Analyzer!")
            print("   Stay safe online! 🔒\n")
            sys.exit(0)
        else:
            print("\n⚠️  Invalid option! Please select 1-5.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Interrupted by user. Goodbye!\n")
        sys.exit(0)
