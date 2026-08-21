import os
from pathlib import Path
from dotenv import load_dotenv

# Single source of truth configuration module
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(BASE_DIR, ".env"))

# Flask Dashboard Settings
FLASK_PORT = int(os.getenv("FLASK_PORT", 5000))
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "False").lower() == "true"
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")

# Database Setup
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"sqlite:///{os.path.join(BASE_DIR, 'database', 'scanner.db')}"
)

# Inspection Engine Limits
MAX_ENDPOINTS = int(os.getenv("MAX_ENDPOINTS", 20))
SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", 30))

# Logging Configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# Central Directory Paths
PAYLOADS_DIR = os.path.join(BASE_DIR, "payloads")
MODELS_DIR   = os.path.join(BASE_DIR, "models")
TABULAR_RANKER_PATH = os.path.join(MODELS_DIR, "tabular_ranker.pkl")
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")
REPORTS_DIR  = os.path.join(BASE_DIR, "reports")

# Trained Machine Learning & Deep Learning Model Artifact Paths
ISOLATION_FOREST_PATH = os.path.join(MODELS_DIR, "isolation_forest.pkl")
LSTM_MODEL_PATH       = os.path.join(MODELS_DIR, "lstm_model.pt")
AUTOENCODER_PATH      = os.path.join(MODELS_DIR, "autoencoder.pt")
