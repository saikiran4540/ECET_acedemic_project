#!/usr/bin/env python
"""
Generate comprehensive real-world phishing detection dataset
Based on known phishing patterns and legitimate URL characteristics
"""

import pandas as pd
import numpy as np
from urllib.parse import urlparse
import re

def extract_url_features(url):
    """Extract 31 features from URL"""
    features = {}
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        
        # Length-based features
        features['url_length'] = len(url)
        features['domain_length'] = len(domain)
        features['path_length'] = len(path)
        features['query_length'] = len(parsed.query)
        
        # Count-based features
        features['dot_count'] = url.count('.')
        features['hyphen_count'] = url.count('-')
        features['underscore_count'] = url.count('_')
        features['slash_count'] = url.count('/')
        features['questionmark_count'] = url.count('?')
        features['equal_count'] = url.count('=')
        features['at_count'] = url.count('@')
        features['and_count'] = url.count('&')
        features['exclamation_count'] = url.count('!')
        features['space_count'] = url.count(' ')
        features['tilde_count'] = url.count('~')
        features['comma_count'] = url.count(',')
        features['plus_count'] = url.count('+')
        features['asterisk_count'] = url.count('*')
        features['hashtag_count'] = url.count('#')
        features['dollar_count'] = url.count('$')
        features['percent_count'] = url.count('%')
        
        # Pattern-based features
        features['has_ip'] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
        features['has_https'] = 1 if parsed.scheme == 'https' else 0
        features['has_http'] = 1 if parsed.scheme == 'http' else 0
        
        # Subdomain features
        subdomain_count = len(domain.split('.')) - 2 if len(domain.split('.')) > 2 else 0
        features['subdomain_count'] = subdomain_count
        
        # Suspicious keywords
        suspicious_keywords = ['verify', 'account', 'update', 'login', 'signin', 'bank', 'secure', 'ebayisapi', 
                             'webscr', 'password', 'confirm', 'urgent', 'click', 'click-here', 'confirm-identity',
                             'appsecure', 'securelogin', 'login-verify', 'ssl-secure']
        features['suspicious_keywords'] = sum(1 for keyword in suspicious_keywords if keyword in url.lower())
        
        # Digit and letter counts
        features['digit_count'] = sum(c.isdigit() for c in url)
        features['letter_count'] = sum(c.isalpha() for c in url)
        
        # Domain token length
        features['domain_token_count'] = len(domain.split('.'))
        features['path_token_count'] = len([p for p in path.split('/') if p])
        
        # Entropy
        if url:
            prob = [float(url.count(c)) / len(url) for c in dict.fromkeys(list(url))]
            features['url_entropy'] = - sum([p * np.log2(p) for p in prob if p > 0])
        else:
            features['url_entropy'] = 0
        
    except Exception as e:
        # Return default features on error
        default_keys = ['url_length', 'domain_length', 'path_length', 'query_length', 'dot_count', 
                       'hyphen_count', 'underscore_count', 'slash_count', 'questionmark_count', 
                       'equal_count', 'at_count', 'and_count', 'exclamation_count', 'space_count',
                       'tilde_count', 'comma_count', 'plus_count', 'asterisk_count', 'hashtag_count',
                       'dollar_count', 'percent_count', 'has_ip', 'has_https', 'has_http',
                       'subdomain_count', 'suspicious_keywords', 'digit_count', 'letter_count',
                       'domain_token_count', 'path_token_count', 'url_entropy']
        for key in default_keys:
            features[key] = 0
    
    return features

def generate_legitimate_urls():
    """Generate legitimate URLs from major companies and services"""
    
    legitimate_domains = [
        # Tech companies
        ('https://www.google.com', 0),
        ('https://www.google.com/search?q=test', 0),
        ('https://www.google.com/maps', 0),
        ('https://www.google.com/drive', 0),
        ('https://docs.google.com', 0),
        ('https://mail.google.com', 0),
        ('https://www.facebook.com', 0),
        ('https://www.facebook.com/login', 0),
        ('https://www.instagram.com', 0),
        ('https://www.instagram.com/login', 0),
        ('https://www.twitter.com', 0),
        ('https://www.twitter.com/login', 0),
        ('https://www.linkedin.com', 0),
        ('https://www.linkedin.com/login', 0),
        ('https://www.youtube.com', 0),
        ('https://www.youtube.com/watch?v=test', 0),
        ('https://github.com', 0),
        ('https://github.com/login', 0),
        ('https://www.microsoft.com', 0),
        ('https://www.microsoft.com/en-us/', 0),
        ('https://outlook.live.com', 0),
        ('https://www.amazon.com', 0),
        ('https://www.amazon.com/s?k=test', 0),
        ('https://www.apple.com', 0),
        ('https://www.apple.com/iphone', 0),
        ('https://support.apple.com', 0),
        ('https://www.wikipedia.org', 0),
        ('https://www.wikipedia.org/wiki/Google', 0),
        ('https://www.stackoverflow.com', 0),
        ('https://www.stackoverflow.com/questions', 0),
        ('https://www.reddit.com', 0),
        ('https://www.reddit.com/r/python', 0),
        ('https://www.medium.com', 0),
        ('https://www.netflix.com', 0),
        ('https://www.netflix.com/login', 0),
        ('https://www.spotify.com', 0),
        ('https://www.spotify.com/login', 0),
        ('https://www.github.com/notifications', 0),
        ('https://www.dropbox.com', 0),
        ('https://www.slack.com', 0),
        ('https://www.slack.com/signin', 0),
        ('https://www.zoom.us', 0),
        ('https://www.zoom.us/signin', 0),
        ('https://www.paypal.com', 0),
        ('https://www.paypal.com/myaccount/homepage', 0),
        ('https://stripe.com', 0),
        ('https://square.com', 0),
        ('https://www.cloudflare.com', 0),
        ('https://www.digitalocean.com', 0),
        ('https://www.heroku.com', 0),
        ('https://www.vercel.com', 0),
        ('https://www.github.com/features', 0),
        ('https://docs.python.org', 0),
        ('https://www.w3schools.com', 0),
        ('https://www.udemy.com', 0),
        ('https://www.coursera.org', 0),
        ('https://www.khan academy.org', 0),
        ('https://www.stackoverflow.com/questions/about', 0),
        ('https://news.ycombinator.com', 0),
        ('https://www.producthunt.com', 0),
        ('https://www.techcrunch.com', 0),
        ('https://www.theverge.com', 0),
        ('https://www.cnn.com', 0),
        ('https://www.bbc.com', 0),
        ('https://www.nytimes.com', 0),
        ('https://www.weather.com', 0),
    ]
    
    return legitimate_domains

def generate_phishing_urls():
    """Generate realistic phishing URLs based on known patterns"""
    
    phishing_urls = [
        # Spoofed Gmail/Google
        ('http://secure-mail-google.com/login', 1),
        ('https://gmail-verify.account-confirmation.com', 1),
        ('https://www.google-account-verify.com', 1),
        ('http://accounts.google.verification.net', 1),
        ('https://google-security-alert.org', 1),
        ('http://update-google.net/secure', 1),
        
        # Spoofed Facebook
        ('https://www.facebook-secure-login.com', 1),
        ('http://facebook-account-verification.net', 1),
        ('https://facebook-login-verify.info', 1),
        ('http://fac3book.com/login', 1),
        ('https://secure.facebook.confirmation.org', 1),
        
        # Spoofed PayPal
        ('https://paypal-account-verify.com', 1),
        ('http://paypal-signin.net/login', 1),
        ('https://www.paypa1.com/login', 1),
        ('http://paypal-secure-verify.org', 1),
        ('https://account-paypal-verify.com/update', 1),
        ('http://update-paypal-account.net/secure', 1),
        
        # Spoofed Amazon
        ('https://amazon-account-verify.com', 1),
        ('http://amaz0n.com/login', 1),
        ('https://amazon-security-check.net', 1),
        ('http://account-amazon-verify.org', 1),
        
        # Spoofed Apple
        ('https://apple-id-verify.com', 1),
        ('http://appleid-account-confirm.net', 1),
        ('https://icloud-security-check.org', 1),
        ('http://update-apple-account.net', 1),
        
        # Banking phishing
        ('https://bank-secure-verify.com', 1),
        ('http://banking-portal-security.net', 1),
        ('https://secure-update-banking.org', 1),
        ('http://verify-bank-account.net', 1),
        
        # IP-based phishing
        ('http://192.168.1.1/admin', 1),
        ('http://10.0.0.1/login', 1),
        ('http://172.16.0.1/bank', 1),
        
        # Long URL with suspicious patterns
        ('https://google.com.verify.secure-account-update.info/login?user=admin&pass=123', 1),
        ('http://paypal.com.security-check.org/account?verify=true&redirect=update', 1),
        
        # Homograph attacks
        ('https://goog1e.com', 1),
        ('https://facebookk.com', 1),
        ('https://amaz0n.net', 1),
        
        # Suspicious subdomains
        ('https://verify.account.paypal.evil.com', 1),
        ('http://login.gmail.super-secure.net', 1),
        ('https://confirm.identity.amazon.verify.org', 1),
        
        # Obfuscated URLs
        ('http://secure-account-verify-update.net/login', 1),
        ('https://account-confirmation-required.org', 1),
        ('http://urgent-security-alert.com/click', 1),
        ('https://immediate-action-required.net', 1),
        
        # Query string exploits
        ('http://legitimate-domain.com@fake-domain.net/login', 1),
        ('https://fake.com#@legitimate.com', 1),
        ('http://legitimate.com%40fake.net', 1),
        
        # Redirect phishing
        ('https://amazon.com.verify.secure.net/account?redirect=login', 1),
        ('http://gmail.security-check.com/verify?comeback=accounts.google.com', 1),
        
        # Multiple subdomains
        ('https://secure.verify.update.confirm.paypal.evil.com', 1),
        ('http://account.login.access.admin.bank.phishing.net', 1),
    ]
    
    return phishing_urls

def generate_dataset(filename='phishing_dataset.csv', total_samples=5000):
    """Generate balanced dataset with realistic phishing and legitimate URLs"""
    
    print("Generating comprehensive phishing detection dataset...")
    
    legitimate_urls = generate_legitimate_urls()
    phishing_urls = generate_phishing_urls()
    
    # Calculate how many samples we need
    phishing_needed = total_samples // 2
    legitimate_needed = total_samples - phishing_needed
    
    # Replicate URLs to reach desired sample count
    all_urls = []
    
    # Add legitimate URLs (replicate with variations)
    for url, label in legitimate_urls:
        all_urls.append((url, label))
    
    # Expand legitimate URLs with variations
    for url, label in legitimate_urls:
        path_variations = ['/about', '/help', '/contact', '/products', '/services', '/blog', '/news']
        for var in path_variations:
            if url.count('/') == 2:  # No existing path
                all_urls.append((url + var, label))
    
    # Add phishing URLs (replicate with variations)
    for url, label in phishing_urls:
        all_urls.append((url, label))
    
    # Expand phishing URLs with variations
    for url, label in phishing_urls:
        # Add query parameters to phishing URLs
        variations = [
            url + '?verify=true',
            url + '?confirm=required',
            url + '?id=12345',
            url + '&update=security',
        ]
        for var in variations:
            all_urls.append((var, label))
    
    # Balance dataset
    legitimate = [u for u in all_urls if u[1] == 0]
    phishing = [u for u in all_urls if u[1] == 1]
    
    # Sample to balance
    np.random.seed(42)
    if len(phishing) > phishing_needed:
        phishing = list(np.random.choice([str(p) for p in phishing], size=phishing_needed, replace=False))
        phishing = [(p[:-3], 1) for p in phishing]  # Convert back to tuple format
    
    if len(legitimate) > legitimate_needed:
        indices = np.random.choice(len(legitimate), size=legitimate_needed, replace=False)
        legitimate = [legitimate[i] for i in indices]
    
    # Combine and create dataframe
    balanced_urls = legitimate + phishing
    np.random.shuffle(balanced_urls)
    
    print(f"Extracting features from {len(balanced_urls)} URLs...")
    
    rows = []
    for url, label in balanced_urls:
        features = extract_url_features(url)
        features['url'] = url
        features['label'] = label
        rows.append(features)
    
    df = pd.DataFrame(rows)
    
    # Reorder columns
    feature_cols = ['url_length', 'domain_length', 'path_length', 'query_length', 'dot_count', 
                   'hyphen_count', 'underscore_count', 'slash_count', 'questionmark_count', 
                   'equal_count', 'at_count', 'and_count', 'exclamation_count', 'space_count',
                   'tilde_count', 'comma_count', 'plus_count', 'asterisk_count', 'hashtag_count',
                   'dollar_count', 'percent_count', 'has_ip', 'has_https', 'has_http',
                   'subdomain_count', 'suspicious_keywords', 'digit_count', 'letter_count',
                   'domain_token_count', 'path_token_count', 'url_entropy', 'url', 'label']
    
    df = df[feature_cols]
    
    # Save dataset
    df.to_csv(filename, index=False)
    
    print(f"\n✓ Dataset generated successfully!")
    print(f"  Total samples: {len(df)}")
    print(f"  Legitimate: {len(df[df['label']==0])} ({len(df[df['label']==0])/len(df)*100:.1f}%)")
    print(f"  Phishing: {len(df[df['label']==1])} ({len(df[df['label']==1])/len(df)*100:.1f}%)")
    print(f"  Features: {len(feature_cols)-2}")  # -2 for url and label
    print(f"  Saved to: {filename}")
    
    return df

if __name__ == '__main__':
    # Generate dataset (can adjust total_samples)
    df = generate_dataset('phishing_dataset.csv', total_samples=5000)
    
    print("\nDataset Statistics:")
    print(f"Shape: {df.shape}")
    print(f"Phishing count: {(df['label']==1).sum()}")
    print(f"Legitimate count: {(df['label']==0).sum()}")
