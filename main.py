import os
import sys
from constants import PROJECT_ROOT, MODULE_DIR

# Add the project root and module directories to Python path
sys.path.extend([PROJECT_ROOT, MODULE_DIR])

from modules.extraction import extract_features
from modules.api_integration import (
    check_openphish,
    check_google_safe_browsing,
    check_virustotal,
)

def analyze_url(url):
    print(f"🔍 Analyzing {url}...")

    # Feature Extraction
    features = extract_features(url)
    print("📊 Extracted Features:", features)

    # API checks
    virustotal_result = check_virustotal(url)
    openphish_result = check_openphish(url)
    google_result = check_google_safe_browsing(url)

    # Display results
    print(f"🔹 VirusTotal: {virustotal_result}")
    print(f"🔹 OpenPhish: {openphish_result}")
    print(f"🔹 Google Safe Browsing: {google_result}")
    print("✅ Analysis completed.")

if __name__ == "__main__":
    url = input("Enter a URL to analyze: ")
    analyze_url(url)
