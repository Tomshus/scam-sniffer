import os
import sys
import requests
import json
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
import base64
import time
from datetime import datetime, timezone
from whoisapi import Client
from whoisapi.models.response import ErrorMessage 

OPENPHISH_API_URL = "https://openphish.com/feed.txt"
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"
GOOGLE_API_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={config.GOOGLE_API_KEY}"
WHOIS_API_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService"

def check_whois(domain):
    """Check domain age using WHOIS API client library."""
    try:
        # Initialize the WHOIS API client
        client = Client(api_key=config.WHOIS_API_KEY)
        
        # Validate domain input
        if not domain:
            raise ValueError("Domain name is missing or invalid.")
        
        # Get domain information
        whois_data = client.data(domain)
        
        if isinstance(whois_data, ErrorMessage):
            print(f"❌ API Error: {whois_data.message}")
            return None, "⚠️ WHOIS lookup failed"
        
        # Debug output
        print("\n🔍 WHOIS Data:")
        print(f"Domain: {getattr(whois_data, 'domain_name', 'N/A')}")
        print(f"Creation Date: {getattr(whois_data, 'created_date', 'N/A')}")
        print(f"Registrar: {getattr(whois_data, 'registrar', 'N/A')}")
        
        if whois_data and getattr(whois_data, 'created_date', None):
            creation_date = whois_data.created_date
            
            # Ensure both datetimes are timezone-aware
            current_time = datetime.now(timezone.utc)
            age_days = (current_time - creation_date).days
            
            # Format the response with better output
            if age_days >= 180:
                return age_days, "✅ Domain age: {} days".format(age_days)
            else:
                return age_days, f"⚠️ Suspicious: Domain is only {age_days} days old!"
                
        elif whois_data and getattr(whois_data, 'domain_availability', None) == 'AVAILABLE':
            return 0, "⚠️ Suspicious: Domain is not registered!"
            
    except Exception as e:
        print(f"❌ WHOIS lookup failed: {str(e)}")
        # Add debug information
        print(f"\nDebug Info:")
        print(f"Domain being checked: {domain}")
    
    return None, "⚠️ Could not determine domain age"

def check_openphish(url):
    """Load OpenPhish feed into a set for fast lookup."""
    """Check if a URL exists in the OpenPhish dataset."""
    try:
        response = requests.get(OPENPHISH_API_URL, timeout=5)
        phishing_urls = set(response.text.split("\n"))
        return "⚠️ Phishing" if url in phishing_urls else "✅ Safe"
    except requests.exceptions.RequestException as e:
        print(f"❌ OpenPhish API error: {e}")
        return "error"
   

def check_google_safe_browsing(url):
    """Check URL using Google Safe Browsing API."""
    try:
        payload = {
            "client": {"clientId": "fraud-detector", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        response = requests.post(GOOGLE_API_URL, json=payload, timeout=5)
        data = response.json()
        return "⚠️ Phishing" if "matches" in data else "✅ Safe"
    except requests.exceptions.RequestException as e:
        print(f"❌ Google Safe Browsing API error: {e}")
        return "error"


def check_virustotal(url):
    """Check URL using VirusTotal API v3."""
    try:
        headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}
        
        print("\n🔍 Checking VirusTotal database...")
        
        # Step 1: Get URL report first
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        report_url = f"{VIRUSTOTAL_API_URL}/urls/{url_id}"
        
        report_response = requests.get(report_url, headers=headers, timeout=10)
        if report_response.status_code == 200:
            report_data = report_response.json()
            last_analysis_stats = report_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = last_analysis_stats.get("malicious", 0)
            
            # Get threat details with better formatting
            threat_names = []
            last_analysis_results = report_data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
            for engine, result in last_analysis_results.items():
                if result.get("category") == "malicious":
                    threat_names.append(f"  • {engine}: {result.get('result', 'unknown')}")
            
            if malicious_count > 0:
                threat_details = "\n".join(threat_names[:3])
                return (
                    f"⛔ Threats Detected\n"
                    f"  • {malicious_count} security vendors flagged this URL\n"
                    f"Details:\n{threat_details}"
                )
            return "✅ No threats detected"
        
        # Step 2: Submit URL for scanning
        print("📥 Submitting URL for analysis...")
        data = {"url": url}
        scan_response = requests.post(f"{VIRUSTOTAL_API_URL}/urls", headers=headers, data=data, timeout=10)
        if scan_response.status_code != 200:
            print(f"❌ Scan request failed (Status: {scan_response.status_code})")
            return "❌ Error submitting URL"

        scan_result = scan_response.json()
        scan_id = scan_result.get("data", {}).get("id", "")
        if not scan_id:
            return "error"

        # Step 3: Wait for analysis to complete
        print("Waiting for analysis to complete...")
        for _ in range(3):  # Try up to 3 times
            result_url = f"{VIRUSTOTAL_API_URL}/analyses/{scan_id}"
            result_response = requests.get(result_url, headers=headers, timeout=10)
            result_data = result_response.json()
            
            status = result_data.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                stats = result_data.get("data", {}).get("attributes", {}).get("stats", {})
                malicious_count = stats.get("malicious", 0)
                return f"⚠️ Phishing (VirusTotal - {malicious_count} detections)" if malicious_count > 0 else "✅ Safe"
            
            time.sleep(3)  # Wait before retrying
            
        return "⚠️ Analysis timeout"
    
    except requests.exceptions.RequestException as e:
        print(f"❌ VirusTotal API error: {e}")
        return "error"