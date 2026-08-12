"""
URL Feature Extractor
Extracts meaningful features from URLs to detect suspicious/phishing links
"""

import re
import tldextract
from urllib.parse import urlparse

class URLFeatureExtractor:
    """Extract features from URLs for machine learning classification"""
    
    def __init__(self):
        # Suspicious keywords commonly found in phishing URLs
        self.suspicious_keywords = [
            'login', 'signin', 'account', 'update', 'verify', 'secure',
            'banking', 'confirm', 'password', 'suspended', 'locked',
            'unusual', 'click', 'free', 'bonus', 'prize', 'winner'
        ]
    
    def extract_features(self, url):
        """
        Extract all features from a given URL
        Returns a dictionary of features
        """
        features = {}
        
        # Basic URL properties
        features['url_length'] = len(url)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_questionmarks'] = url.count('?')
        features['num_equals'] = url.count('=')
        features['num_at'] = url.count('@')
        features['num_ampersand'] = url.count('&')
        features['num_percent'] = url.count('%')
        
        # Check for HTTPS
        features['has_https'] = 1 if url.startswith('https://') else 0
        
        # Check for IP address instead of domain name
        features['has_ip'] = self._has_ip_address(url)
        
        # Check for suspicious keywords
        features['num_suspicious_keywords'] = self._count_suspicious_keywords(url)
        
        # Extract domain and subdomain features
        extracted = tldextract.extract(url)
        features['subdomain_length'] = len(extracted.subdomain) if extracted.subdomain else 0
        features['domain_length'] = len(extracted.domain) if extracted.domain else 0
        features['num_subdomains'] = extracted.subdomain.count('.') + 1 if extracted.subdomain else 0
        
        # Check for abnormal URL patterns
        features['has_double_slash'] = 1 if '//' in url[8:] else 0  # After protocol
        features['num_digits'] = sum(c.isdigit() for c in url)
        features['num_special_chars'] = len(re.findall(r'[^a-zA-Z0-9]', url))
        
        # Ratio features (normalized metrics)
        if len(url) > 0:
            features['digits_ratio'] = features['num_digits'] / len(url)
            features['special_chars_ratio'] = features['num_special_chars'] / len(url)
        else:
            features['digits_ratio'] = 0
            features['special_chars_ratio'] = 0
        
        return features
    
    def _has_ip_address(self, url):
        """Check if URL contains an IP address instead of domain name"""
        # IPv4 pattern
        ipv4_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
        # IPv6 pattern (simplified)
        ipv6_pattern = re.compile(r'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}')
        
        if ipv4_pattern.search(url) or ipv6_pattern.search(url):
            return 1
        return 0
    
    def _count_suspicious_keywords(self, url):
        """Count how many suspicious keywords appear in the URL"""
        url_lower = url.lower()
        count = 0
        for keyword in self.suspicious_keywords:
            if keyword in url_lower:
                count += 1
        return count
    
    def get_feature_names(self):
        """Return list of all feature names in order"""
        return [
            'url_length', 'num_dots', 'num_hyphens', 'num_underscores',
            'num_slashes', 'num_questionmarks', 'num_equals', 'num_at',
            'num_ampersand', 'num_percent', 'has_https', 'has_ip',
            'num_suspicious_keywords', 'subdomain_length', 'domain_length',
            'num_subdomains', 'has_double_slash', 'num_digits',
            'num_special_chars', 'digits_ratio', 'special_chars_ratio'
        ]
    
    def explain_features(self, features):
        """
        Generate human-readable explanation of suspicious features
        Returns list of reasons why a URL might be suspicious
        """
        reasons = []
        
        if features['url_length'] > 100:
            reasons.append(f"⚠️ Very long URL ({features['url_length']} characters)")
        
        if features['has_https'] == 0:
            reasons.append("⚠️ No HTTPS encryption")
        
        if features['has_ip'] == 1:
            reasons.append("⚠️ Uses IP address instead of domain name")
        
        if features['num_suspicious_keywords'] > 0:
            reasons.append(f"⚠️ Contains {features['num_suspicious_keywords']} suspicious keyword(s)")
        
        if features['num_dots'] > 5:
            reasons.append(f"⚠️ Unusual number of dots ({features['num_dots']})")
        
        if features['num_at'] > 0:
            reasons.append("⚠️ Contains '@' symbol (possible URL obfuscation)")
        
        if features['has_double_slash'] == 1:
            reasons.append("⚠️ Contains '//' after domain (possible redirection)")
        
        if features['num_hyphens'] > 3:
            reasons.append(f"⚠️ Many hyphens ({features['num_hyphens']}) - possible domain mimicking")
        
        if features['num_subdomains'] > 3:
            reasons.append(f"⚠️ Many subdomains ({features['num_subdomains']}) - unusual structure")
        
        if features['digits_ratio'] > 0.3:
            reasons.append(f"⚠️ High proportion of digits ({features['digits_ratio']:.1%})")
        
        return reasons
