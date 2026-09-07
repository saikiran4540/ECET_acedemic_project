from urllib.parse import urlparse
import re
import numpy as np

def is_valid_email(input_text):
    """Check if input is a valid email address"""
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_pattern, input_text.strip()) is not None

def is_valid_url(input_text):
    """Check if input is a valid URL"""
    url_pattern = r'^(https?|ftp)://[^\s/$.?#].[^\s]*$'
    return re.match(url_pattern, input_text.strip(), re.IGNORECASE) is not None

def extract_email_features(email):
    """Extract features from email address for prediction"""
    features = {}
    
    try:
        email = email.strip().lower()
        
        # Split email into local and domain parts
        if '@' not in email:
            # Invalid email, return default features
            for key in ['url_length', 'domain_length', 'path_length', 'query_length', 'dot_count', 
                       'hyphen_count', 'underscore_count', 'slash_count', 'questionmark_count', 
                       'equal_count', 'at_count', 'and_count', 'exclamation_count', 'space_count',
                       'tilde_count', 'comma_count', 'plus_count', 'asterisk_count', 'hashtag_count',
                       'dollar_count', 'percent_count', 'has_ip', 'has_https', 'has_http',
                       'subdomain_count', 'suspicious_keywords', 'digit_count', 'letter_count',
                       'domain_token_count', 'path_token_count', 'url_entropy']:
                features[key] = 0
            return features
        
        local_part, domain_part = email.rsplit('@', 1)
        
        # Length-based features
        features['url_length'] = len(email)
        features['domain_length'] = len(domain_part)
        features['path_length'] = len(local_part)  # Local part acts as path for consistency
        features['query_length'] = 0
        
        # Count-based features
        features['dot_count'] = email.count('.')
        features['hyphen_count'] = email.count('-')
        features['underscore_count'] = email.count('_')
        features['slash_count'] = email.count('/')
        features['questionmark_count'] = email.count('?')
        features['equal_count'] = email.count('=')
        features['at_count'] = email.count('@')  # Should be 1 for valid email
        features['and_count'] = email.count('&')
        features['exclamation_count'] = email.count('!')
        features['space_count'] = email.count(' ')
        features['tilde_count'] = email.count('~')
        features['comma_count'] = email.count(',')
        features['plus_count'] = email.count('+')
        features['asterisk_count'] = email.count('*')
        features['hashtag_count'] = email.count('#')
        features['dollar_count'] = email.count('$')
        features['percent_count'] = email.count('%')
        
        # Pattern-based features
        features['has_ip'] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain_part) else 0
        features['has_https'] = 0  # Emails don't have https
        features['has_http'] = 0   # Emails don't have http
        
        # Subdomain features (from domain part)
        domain_parts = domain_part.split('.')
        features['subdomain_count'] = len(domain_parts) - 2 if len(domain_parts) > 2 else 0
        
        # Suspicious keywords in email
        suspicious_keywords = ['verify', 'account', 'update', 'login', 'signin', 'bank', 'secure', 'password', 'confirm', 'urgent', 'click']
        features['suspicious_keywords'] = sum(1 for keyword in suspicious_keywords if keyword in email)
        
        # Digit and letter counts
        features['digit_count'] = sum(c.isdigit() for c in email)
        features['letter_count'] = sum(c.isalpha() for c in email)
        
        # Domain token count
        features['domain_token_count'] = len(domain_parts)
        features['path_token_count'] = len(local_part.split('.'))  # Local part tokens
        
        # Entropy
        features['url_entropy'] = calculate_entropy(email)
        
    except Exception as e:
        print(f"Error extracting email features: {e}")
        # Return default features
        for key in ['url_length', 'domain_length', 'path_length', 'query_length', 'dot_count', 
                   'hyphen_count', 'underscore_count', 'slash_count', 'questionmark_count', 
                   'equal_count', 'at_count', 'and_count', 'exclamation_count', 'space_count',
                   'tilde_count', 'comma_count', 'plus_count', 'asterisk_count', 'hashtag_count',
                   'dollar_count', 'percent_count', 'has_ip', 'has_https', 'has_http',
                   'subdomain_count', 'suspicious_keywords', 'digit_count', 'letter_count',
                   'domain_token_count', 'path_token_count', 'url_entropy']:
            features[key] = 0
    
    return features

def extract_url_features(url):
    """Extract features from URL for prediction"""
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
        suspicious_keywords = ['verify', 'account', 'update', 'login', 'signin', 'bank', 'secure', 'ebayisapi', 'webscr', 'password', 'confirm']
        features['suspicious_keywords'] = sum(1 for keyword in suspicious_keywords if keyword in url.lower())
        
        # Digit and letter counts
        features['digit_count'] = sum(c.isdigit() for c in url)
        features['letter_count'] = sum(c.isalpha() for c in url)
        
        # Domain token length
        features['domain_token_count'] = len(domain.split('.'))
        features['path_token_count'] = len([p for p in path.split('/') if p])
        
        # Entropy
        features['url_entropy'] = calculate_entropy(url)
        
    except Exception as e:
        print(f"Error extracting features: {e}")
        # Return default features
        for key in ['url_length', 'domain_length', 'path_length', 'query_length', 'dot_count', 
                   'hyphen_count', 'underscore_count', 'slash_count', 'questionmark_count', 
                   'equal_count', 'at_count', 'and_count', 'exclamation_count', 'space_count',
                   'tilde_count', 'comma_count', 'plus_count', 'asterisk_count', 'hashtag_count',
                   'dollar_count', 'percent_count', 'has_ip', 'has_https', 'has_http',
                   'subdomain_count', 'suspicious_keywords', 'digit_count', 'letter_count',
                   'domain_token_count', 'path_token_count', 'url_entropy']:
            features[key] = 0
    
    return features

def calculate_entropy(string):
    """Calculate Shannon entropy"""
    if not string:
        return 0
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    entropy = - sum([p * np.log2(p) for p in prob if p > 0])
    return entropy

def get_feature_importance_explanation(features, top_n=5):
    """Get top contributing features for explanation"""
    # Define feature weights (based on common phishing indicators)
    feature_weights = {
        'suspicious_keywords': 5,
        'has_ip': 4,
        'url_length': 3,
        'subdomain_count': 3,
        'at_count': 4,
        'hyphen_count': 2,
        'dot_count': 2,
    }
    
    explanations = []
    for feature, value in features.items():
        if feature in feature_weights and value > 0:
            weight = feature_weights[feature]
            score = value * weight
            explanations.append((feature, value, score))
    
    # Sort by score and get top N
    explanations.sort(key=lambda x: x[2], reverse=True)
    
    return explanations[:top_n]
def detect_input_type(input_text):
    """Detect if input is URL or Email and return type"""
    input_text = input_text.strip()
    
    if is_valid_email(input_text):
        return 'email'
    elif is_valid_url(input_text):
        return 'url'
    else:
        # Try to be lenient and guess
        if '@' in input_text and '://' not in input_text:
            return 'email'
        elif '://' in input_text or input_text.startswith('www.'):
            return 'url'
        else:
            # Default to URL if ambiguous
            return 'url'

def extract_features(input_text, input_type=None):
    """Extract features based on input type (auto-detect if not specified)"""
    if input_type is None:
        input_type = detect_input_type(input_text)
    
    if input_type == 'email':
        return extract_email_features(input_text), 'email'
    else:
        return extract_url_features(input_text), 'url'