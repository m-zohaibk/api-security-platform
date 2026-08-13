import os
import sys
from pathlib import Path
from typing import List, Dict, Any
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.response_parser import ResponseParser
from config.logging_config import logger
from config.settings import DATASETS_DIR

class DatasetPreparer:
    """
    Loads, cleans, and extracts 12 numerical features from HTTP request datasets
    (such as HTTP CSIC 2010) for Isolation Forest and Deep Learning anomaly models.
    """

    FEATURE_COLUMNS = [
        "encoded_method",
        "path_depth",
        "url_length",
        "query_param_count",
        "query_string_length",
        "payload_length",
        "payload_entropy",
        "special_char_count",
        "header_count",
        "auth_header_present",
        "status_code",
        "response_size"
    ]

    def __init__(self, raw_dir: str = None, processed_dir: str = None):
        self.raw_dir = Path(raw_dir) if raw_dir else Path(DATASETS_DIR) / "raw" / "csic_2010"
        self.processed_dir = Path(processed_dir) if processed_dir else Path(DATASETS_DIR) / "processed"
        self.processed_dir.mkdir(parents=True, exist_ok=True)
        self.parser = ResponseParser()

    def parse_csic_raw_text(self, file_path: Path, label: int) -> List[Dict[str, Any]]:
        """Parses HTTP request blocks from raw CSIC 2010 text dataset files."""
        records = []
        if not file_path.exists():
            return records

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        # CSIC dataset separates requests by blank lines / HTTP method headers
        raw_requests = content.split("\n\nPOST ")
        if len(raw_requests) == 1:
            raw_requests = content.split("\n\nGET ")

        for raw_req in raw_requests:
            if not raw_req.strip():
                continue
            
            lines = raw_req.strip().split("\n")
            first_line = lines[0].strip()
            parts = first_line.split(" ")
            
            method = parts[0] if parts[0] in ["GET", "POST", "PUT", "DELETE"] else "GET"
            url_path = parts[1] if len(parts) > 1 else "/"
            full_url = f"http://localhost{url_path}"

            # Extract body if POST
            body = ""
            if "" in lines:
                idx = lines.index("")
                body = "\n".join(lines[idx + 1:])

            sample_resp_data = {
                "method": method,
                "url": full_url,
                "payload": body,
                "status_code": 200,
                "response_size": len(body),
                "request_headers": {"User-Agent": "CSIC-Parser"}
            }

            features = self.parser.extract_features(sample_resp_data)
            features["label"] = label
            records.append(features)

        return records

    def parse_csic_csv(self, csv_path: Path) -> List[Dict[str, Any]]:
        """Parses HTTP request records from csic_database.csv file."""
        records = []
        if not csv_path.exists():
            return records

        logger.info(f"Parsing CSIC 2010 database CSV from {csv_path}...")
        raw_df = pd.read_csv(csv_path, low_memory=False)

        for _, row in raw_df.iterrows():
            method = str(row.get("Method", "GET")).strip().upper()
            if method not in ["GET", "POST", "PUT", "DELETE"]:
                method = "GET"
            
            raw_url = str(row.get("URL", "/"))
            url_path = raw_url.split(" ")[0] if " " in raw_url else raw_url
            if not url_path.startswith("http"):
                url_path = f"http://localhost:8080{url_path}"

            payload = str(row.get("content", "")) if pd.notna(row.get("content")) else ""
            if payload == "nan":
                payload = ""

            try:
                label = int(row.get("classification", 0))
            except (ValueError, TypeError):
                label = 0

            sample_req = {
                "method": method,
                "url": url_path,
                "payload": payload,
                "status_code": 0,
                "response_size": 0,
                "request_headers": {"User-Agent": str(row.get("User-Agent", ""))}
            }

            features = self.parser.extract_features(sample_req)
            features["label"] = label
            records.append(features)

        return records

    def generate_synthetic_csic_fallback(self, num_samples: int = 1000) -> pd.DataFrame:
        """Generates representative baseline HTTP feature samples if raw files are absent."""
        logger.info("Raw CSIC dataset files not found. Generating baseline dataset samples...")
        np.random.seed(42)

        data = []
        for i in range(num_samples):
            is_attack = 1 if i % 4 == 0 else 0
            
            if is_attack:
                method = np.random.choice([1, 2, 3, 4])
                depth = np.random.randint(1, 6)
                url_len = np.random.randint(30, 150)
                param_count = np.random.randint(2, 10)
                qs_len = np.random.randint(20, 120)
                payload_len = np.random.randint(50, 300)
                entropy = round(np.random.uniform(4.5, 7.5), 4)
                special_count = np.random.randint(10, 50)
                header_count = np.random.randint(3, 12)
                auth_present = np.random.choice([0, 1])
                status = np.random.choice([200, 400, 403, 500])
                size = np.random.randint(100, 5000)
            else:
                method = np.random.choice([1, 2], p=[0.7, 0.3])
                depth = np.random.randint(1, 4)
                url_len = np.random.randint(15, 50)
                param_count = np.random.randint(0, 3)
                qs_len = np.random.randint(0, 30)
                payload_len = np.random.randint(0, 50)
                entropy = round(np.random.uniform(1.0, 4.0), 4)
                special_count = np.random.randint(0, 5)
                header_count = np.random.randint(4, 8)
                auth_present = 1
                status = 200
                size = np.random.randint(200, 1500)

            sample = {
                "encoded_method": method,
                "path_depth": depth,
                "url_length": url_len,
                "query_param_count": param_count,
                "query_string_length": qs_len,
                "payload_length": payload_len,
                "payload_entropy": entropy,
                "special_char_count": special_count,
                "header_count": header_count,
                "auth_header_present": auth_present,
                "status_code": status,
                "response_size": size,
                "label": is_attack
            }
            data.append(sample)

        return pd.DataFrame(data)

    def prepare(self) -> pd.DataFrame:
        logger.info("Preparing dataset and extracting HTTP numerical features...")
        
        all_records = []

        # Check for standard CSIC 2010 dataset files (CSV or raw TXT)
        csic_csv_file = self.raw_dir / "csic_database.csv"
        train_normal_file = self.raw_dir / "normalTrafficTraining.txt"
        test_normal_file = self.raw_dir / "normalTrafficTest.txt"
        test_attack_file = self.raw_dir / "anomalousTrafficTest.txt"

        if csic_csv_file.exists():
            all_records.extend(self.parse_csic_csv(csic_csv_file))
            df = pd.DataFrame(all_records)
        elif train_normal_file.exists() or test_attack_file.exists():
            all_records.extend(self.parse_csic_raw_text(train_normal_file, label=0))
            all_records.extend(self.parse_csic_raw_text(test_normal_file, label=0))
            all_records.extend(self.parse_csic_raw_text(test_attack_file, label=1))
            df = pd.DataFrame(all_records)
        else:
            df = self.generate_synthetic_csic_fallback()

        # Clean data — handle missing values
        if "feature_vector" in df.columns:
            df = df.drop(columns=["feature_vector"])
        df = df.dropna().drop_duplicates(subset=self.FEATURE_COLUMNS + ["label"])

        # Split train (80%) and test (20%)
        train_df, test_df = train_test_split(df, test_size=0.20, random_state=42, stratify=df["label"])

        # Save processed CSV files
        train_path = self.processed_dir / "train.csv"
        test_path = self.processed_dir / "test.csv"
        features_path = self.processed_dir / "features.csv"

        train_df.to_csv(train_path, index=False)
        test_df.to_csv(test_path, index=False)
        df.to_csv(features_path, index=False)

        # Print statistics
        total_samples = len(df)
        normal_count = len(df[df["label"] == 0])
        attack_count = len(df[df["label"] == 1])

        print("\n" + "="*50)
        print(" DATASET PREPARATION SUMMARY")
        print("="*50)
        print(f" Total Samples Processed : {total_samples}")
        print(f" Normal Samples (0)      : {normal_count}")
        print(f" Attack Samples (1)      : {attack_count}")
        print(f" Training Set Size (80%) : {len(train_df)}")
        print(f" Testing Set Size (20%)  : {len(test_df)}")
        print(f" Extracted Feature Names : {self.FEATURE_COLUMNS}")
        print(f" Saved Datasets To       : {self.processed_dir}")
        print("="*50 + "\n")

        return df


if __name__ == "__main__":
    preparer = DatasetPreparer()
    preparer.prepare()
