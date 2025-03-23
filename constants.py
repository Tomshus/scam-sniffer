import os

# Define project root directory
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
MODULE_DIR = os.path.join(PROJECT_ROOT, 'module')

# Create directories if they don't exist
os.makedirs(MODULE_DIR, exist_ok=True)