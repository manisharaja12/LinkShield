"""
Dataset Loader
Downloads or creates a sample dataset of malicious and legitimate URLs
"""

import pandas as pd
import requests
import os

class DatasetLoader:
    """Load or create URL dataset for training"""
    
    def __init__(self):
        self.dataset_path = 'url_dataset.csv'
    
    def create_sample_dataset(self):
        """
        Create a sample dataset with malicious and legitimate URLs
        This is used when the full dataset isn't available
        """
        print("Creating sample dataset...")
        
        # Sample malicious URLs (phishing patterns)
        malicious_urls = [
            'http://125.98.3.123/fake.html',
            'http://paypal-verify.com/update-account.php',
            'https://accounts-google.com/signin/verify',
            'http://secure-login-amazon.com/ap/signin',
            'http://www.paypal.com-security-update.com/login.php',
            'https://facebook-security.com/checkpoint',
            'http://apple.com-locked.verify.account.com',
            'https://netflix.account-update.net/billing',
            'http://192.168.1.1/admin/login.php',
            'https://secure.login-amazon.account-verify.com',
            'http://microsoft-account-recovery.net/update',
            'https://your-bank-secure-login.com/verify',
            'http://paypal.com-signin.verify-account.net',
            'https://instagram-security-check.com/password',
            'http://amazon.com.security-check.net/signin',
            'https://update-account-information.net/login',
            'http://account-suspended-verify-now.com',
            'https://linkedin-premium-free-trial.net',
            'http://google.com-verify.account-recovery.net',
            'https://twitter-verify.com/account/suspended',
            'http://banking-secure-login.net/accounts',
            'https://paypal.confirm-account.net/update.php',
            'http://microsoft-office-activation.net/verify',
            'https://apple-id.verify.account.net/signin',
            'http://facebook.com-security.verify.net',
            'https://amazon-prize-winner.com/claim',
            'http://verify-your-account-now.net/login',
            'https://secure.account-update.verify.com',
            'http://unusual-activity-detected.com/verify',
            'https://click-here-to-claim-bonus.net',
            'http://free-premium-account-upgrade.com',
            'https://account.locked-verify.now.net',
            'http://confirm-identity-suspended-account.com',
            'https://update-payment-information.verify.net',
            'http://security-alert-verify-now.com/signin',
        ]
        
        # Sample legitimate URLs
        legitimate_urls = [
            'https://www.google.com',
            'https://www.github.com/username/repository',
            'https://stackoverflow.com/questions/12345',
            'https://www.wikipedia.org/wiki/Machine_Learning',
            'https://www.amazon.com/product/B08N5WRWNW',
            'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
            'https://www.reddit.com/r/programming',
            'https://www.nytimes.com/2024/01/01/technology',
            'https://www.bbc.com/news/technology',
            'https://docs.python.org/3/library/re.html',
            'https://www.netflix.com/browse',
            'https://www.linkedin.com/in/username',
            'https://www.facebook.com/username',
            'https://twitter.com/username',
            'https://www.instagram.com/username',
            'https://medium.com/@author/article-title',
            'https://www.paypal.com/us/home',
            'https://www.microsoft.com/en-us/windows',
            'https://www.apple.com/iphone',
            'https://www.spotify.com/us/',
            'https://mail.google.com/mail/u/0',
            'https://drive.google.com/drive/my-drive',
            'https://www.dropbox.com/home',
            'https://www.salesforce.com',
            'https://www.adobe.com/products/photoshop',
            'https://www.atlassian.com/software/jira',
            'https://www.slack.com/workspace',
            'https://www.notion.so/product',
            'https://www.figma.com/files/recent',
            'https://www.canva.com/designs',
            'https://www.coursera.org/courses',
            'https://www.udemy.com/courses',
            'https://www.edx.org/learn',
            'https://www.khanacademy.org/computing',
            'https://www.w3schools.com/python',
        ]
        
        # Create DataFrame
        df = pd.DataFrame({
            'url': malicious_urls + legitimate_urls,
            'label': ['malicious'] * len(malicious_urls) + ['legitimate'] * len(legitimate_urls)
        })
        
        # Shuffle the dataset
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        # Save to CSV
        df.to_csv(self.dataset_path, index=False)
        print(f"✓ Sample dataset created: {self.dataset_path}")
        print(f"  - Total URLs: {len(df)}")
        print(f"  - Malicious: {(df['label'] == 'malicious').sum()}")
        print(f"  - Legitimate: {(df['label'] == 'legitimate').sum()}")
        
        return df
    
    def load_dataset(self):
        """
        Load the dataset (create sample if doesn't exist)
        Returns DataFrame with 'url' and 'label' columns
        """
        if os.path.exists(self.dataset_path):
            print(f"Loading dataset from {self.dataset_path}...")
            df = pd.read_csv(self.dataset_path)
            print(f"✓ Dataset loaded: {len(df)} URLs")
            return df
        else:
            print("Dataset not found. Creating sample dataset...")
            return self.create_sample_dataset()
    
    def download_kaggle_dataset(self):
        """
        Instructions for downloading the full Kaggle dataset
        Requires Kaggle API credentials
        """
        print("\n" + "="*60)
        print("TO DOWNLOAD FULL KAGGLE DATASET:")
        print("="*60)
        print("\n1. Install Kaggle CLI:")
        print("   pip install kaggle")
        print("\n2. Set up Kaggle API credentials:")
        print("   - Go to https://www.kaggle.com/settings")
        print("   - Click 'Create New API Token'")
        print("   - Place kaggle.json in ~/.kaggle/")
        print("\n3. Download the dataset:")
        print("   kaggle datasets download -d sid321axn/malicious-urls-dataset")
        print("   unzip malicious-urls-dataset.zip")
        print("   mv malicious_phish.csv url_dataset.csv")
        print("\n4. Re-run the training script")
        print("="*60 + "\n")

if __name__ == "__main__":
    loader = DatasetLoader()
    loader.download_kaggle_dataset()
    df = loader.load_dataset()
    print(f"\nDataset preview:")
    print(df.head(10))
    print(f"\nLabel distribution:")
    print(df['label'].value_counts())
