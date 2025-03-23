import re
import whois
import requests
from datetime import datetime, timezone
from urllib.parse import urlparse
from api_integration import check_whois

# List of suspicious words commonly found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "secure", "login", "verify", "banking", "update", "account", "payment",
    "billing", "webscr", "confirm", "security", "support", "service"
]

def get_domain_age(domain):
    """Calculate domain age in days with API fallback."""
    # First try with python-whois
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):  # Handle multiple dates
            creation_date = creation_date[0]

        if creation_date:
            # Ensure creation_date is timezone-aware
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)

            # Calculate age
            age_days = (datetime.now(timezone.utc) - creation_date).days
            if age_days >= 180:
                return age_days, None
            else:
                return age_days, "⚠️ This domain is new!"
        else:
            print("⚠️ Unable to determine domain age using python-whois.")
    except Exception as e:
        print(f"❌ Primary WHOIS lookup failed: {str(e)}. Trying API fallback...")

    # Fallback to WHOIS API
    try:
        age, message = check_whois(domain)
        if age is not None:
            print(f"\n🔍 WHOIS Data:")
            print(f"Domain: {domain}")
            print(f"Creation Date: {getattr(check_whois(domain), 'created_date', 'N/A')}")
            print(f"Registrar: {getattr(check_whois(domain), 'registrar', 'N/A')}")
            print(f"🔹 Domain Age: {age} days")
            print(f"🔹 Status: {message}")
        return age, message
    except Exception as e:
        print(f"❌ API fallback failed: {str(e)}")
    
    return None, "⚠️ Both WHOIS lookup methods failed."

def check_https(url):
    """Check if URL uses HTTPS."""
    return url.startswith("https"), "⚠️ No HTTPS detected!" if not url.startswith("https") else None

def count_special_chars(url):
    """Count suspicious special characters in URL."""
    special_chars = ['@', '-', '_', '?', '=', '&']
    count = sum(url.count(char) for char in special_chars)
    
    return count, "⚠️ Suspicious URL: Too many special characters!" if count > 3 else None

def count_redirects(url):
    """Check the number of redirects for a given URL."""
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        redirect_count = len(response.history)
        
        return redirect_count, "⚠️ Too many redirects!" if redirect_count > 3 else None
    except requests.exceptions.RequestException:
        return None, "⚠️ Could not determine redirects (Request failed)."

def contains_ip(url):
    """Check if the URL contains an IP address instead of a domain name."""
    ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'  # Simple IPv4 regex
    match = re.search(ip_pattern, url)
    
    return bool(match), "⚠️ URL contains an IP address instead of a domain!" if match else None

def check_suspicious_keywords(url):
    """Check for suspicious phishing-related keywords in the URL."""
    found_keywords = [word for word in SUSPICIOUS_KEYWORDS if word in url.lower()]
    
    return found_keywords, f"⚠️ Suspicious keywords found in URL: {', '.join(found_keywords)}" if found_keywords else None

def extract_features(url):
    """Extract various features from the URL."""
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.strip()  # Ensure domain is properly extracted
    if not domain:
        print("❌ Invalid URL: Could not extract domain.")
        return {"Error": "Invalid URL"}

    print(f"🔍 Domain: {domain}")
    
    # Extract Features
    url_length = len(url)
    domain_age, domain_warning = get_domain_age(domain)
    uses_https, https_warning = check_https(url)
    special_chars_count, special_chars_warning = count_special_chars(url)
    redirect_count, redirect_warning = count_redirects(url)
    has_ip, ip_warning = contains_ip(url)
    suspicious_keywords, keywords_warning = check_suspicious_keywords(url)

    # Feature Dictionary
    features = {
        "URL Length": url_length,
        "Domain Age (days)": domain_age if domain_age else "Unknown",
        "Uses HTTPS": uses_https,
        "Special Characters Count": special_chars_count,
        "Redirect Count": redirect_count if redirect_count is not None else "Unknown",
        "Contains IP": has_ip,
        "Suspicious Keywords": suspicious_keywords if suspicious_keywords else "None"
    }

    # Print Warnings
    warnings = [w for w in [domain_warning, https_warning, special_chars_warning, redirect_warning, ip_warning, keywords_warning] if w]
    if warnings:
        print("\n⚠️ Warnings:")
        for warning in warnings:
            print(warning)

    return features
