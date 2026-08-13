import pytest
import pandas as pd
from pathlib import Path
from config.settings import DATASETS_DIR

def test_processed_dataset_files():
    processed_dir = Path(DATASETS_DIR) / "processed"
    train_file = processed_dir / "train.csv"
    test_file = processed_dir / "test.csv"
    features_file = processed_dir / "features.csv"

    # Verify that files exist or can be read
    if train_file.exists():
        df = pd.read_csv(train_file)
        assert len(df) > 0
        assert "encoded_method" in df.columns
        assert "label" in df.columns

def test_self_generated_dataset():
    self_dir = Path(DATASETS_DIR) / "self_generated"
    vampi_file = self_dir / "vampi_scans.csv"

    if vampi_file.exists():
        df = pd.read_csv(vampi_file)
        assert len(df) > 0
        assert "label" in df.columns
