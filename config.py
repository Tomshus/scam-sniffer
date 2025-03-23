import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get API keys from environment variables
GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
WHOIS_API_KEY = os.getenv('WHOIS_API_KEY')

# Validate API keys
if not all([GOOGLE_API_KEY, VIRUSTOTAL_API_KEY, WHOIS_API_KEY]):
    raise ValueError("Missing required API keys in environment variables")