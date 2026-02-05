"""
Data Loader for Intrusion Detection System
Handles loading and preprocessing of network traffic data
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
import pickle
import os


class IDSDataLoader:
    """Load and preprocess network intrusion detection data"""

    def __init__(self, data_path=None):
        self.data_path = data_path
        self.label_encoder = LabelEncoder()
        self.scaler = StandardScaler()
        self.feature_names = None
        self.protocol_encoder = LabelEncoder()
        self.service_encoder = LabelEncoder()
        self.flag_encoder = LabelEncoder()

        # NSL-KDD column names
        self.column_names = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
            'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
            'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
            'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
            'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
            'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
        ]

    def create_sample_data(self, n_samples=10000):
        """Create synthetic network traffic data for demonstration"""
        np.random.seed(42)

        # Generate normal traffic (70%)
        n_normal = int(n_samples * 0.7)
        normal_data = {
            'duration': np.random.exponential(2, n_normal),
            'protocol_type': np.random.choice(['tcp', 'udp', 'icmp'], n_normal, p=[0.7, 0.2, 0.1]),
            'service': np.random.choice(['http', 'ftp', 'smtp', 'ssh', 'dns'], n_normal),
            'flag': np.random.choice(['SF', 'S0', 'REJ'], n_normal, p=[0.8, 0.15, 0.05]),
            'src_bytes': np.random.lognormal(7, 2, n_normal).astype(int),
            'dst_bytes': np.random.lognormal(8, 2, n_normal).astype(int),
            'land': np.zeros(n_normal),
            'wrong_fragment': np.random.poisson(0.1, n_normal),
            'urgent': np.zeros(n_normal),
            'hot': np.random.poisson(0.5, n_normal),
            'num_failed_logins': np.zeros(n_normal),
            'logged_in': np.ones(n_normal),
            'num_compromised': np.zeros(n_normal),
            'root_shell': np.zeros(n_normal),
            'su_attempted': np.zeros(n_normal),
            'num_root': np.random.poisson(0.2, n_normal),
            'num_file_creations': np.random.poisson(1, n_normal),
            'num_shells': np.zeros(n_normal),
            'num_access_files': np.random.poisson(0.5, n_normal),
            'num_outbound_cmds': np.zeros(n_normal),
            'is_host_login': np.zeros(n_normal),
            'is_guest_login': np.zeros(n_normal),
            'count': np.random.randint(1, 100, n_normal),
            'srv_count': np.random.randint(1, 100, n_normal),
            'serror_rate': np.random.uniform(0, 0.2, n_normal),
            'srv_serror_rate': np.random.uniform(0, 0.2, n_normal),
            'rerror_rate': np.random.uniform(0, 0.2, n_normal),
            'srv_rerror_rate': np.random.uniform(0, 0.2, n_normal),
            'same_srv_rate': np.random.uniform(0.7, 1.0, n_normal),
            'diff_srv_rate': np.random.uniform(0, 0.3, n_normal),
            'srv_diff_host_rate': np.random.uniform(0, 0.3, n_normal),
            'dst_host_count': np.random.randint(1, 255, n_normal),
            'dst_host_srv_count': np.random.randint(1, 255, n_normal),
            'dst_host_same_srv_rate': np.random.uniform(0.7, 1.0, n_normal),
            'dst_host_diff_srv_rate': np.random.uniform(0, 0.3, n_normal),
            'dst_host_same_src_port_rate': np.random.uniform(0.5, 1.0, n_normal),
            'dst_host_srv_diff_host_rate': np.random.uniform(0, 0.3, n_normal),
            'dst_host_serror_rate': np.random.uniform(0, 0.2, n_normal),
            'dst_host_srv_serror_rate': np.random.uniform(0, 0.2, n_normal),
            'dst_host_rerror_rate': np.random.uniform(0, 0.2, n_normal),
            'dst_host_srv_rerror_rate': np.random.uniform(0, 0.2, n_normal),
            'label': ['normal'] * n_normal,
            'difficulty': np.zeros(n_normal)
        }

        # Generate DoS attacks (15%)
        n_dos = int(n_samples * 0.15)
        dos_data = {
            'duration': np.random.exponential(0.5, n_dos),
            'protocol_type': np.random.choice(['tcp', 'udp', 'icmp'], n_dos, p=[0.5, 0.3, 0.2]),
            'service': np.random.choice(['http', 'ftp', 'smtp'], n_dos),
            'flag': np.random.choice(['SF', 'S0', 'REJ', 'RSTO'], n_dos, p=[0.3, 0.4, 0.2, 0.1]),
            'src_bytes': np.random.lognormal(5, 1.5, n_dos).astype(int),
            'dst_bytes': np.random.lognormal(4, 1, n_dos).astype(int),
            'land': np.zeros(n_dos),
            'wrong_fragment': np.random.poisson(0.3, n_dos),
            'urgent': np.random.poisson(0.5, n_dos),
            'hot': np.random.poisson(2, n_dos),
            'num_failed_logins': np.zeros(n_dos),
            'logged_in': np.zeros(n_dos),
            'num_compromised': np.zeros(n_dos),
            'root_shell': np.zeros(n_dos),
            'su_attempted': np.zeros(n_dos),
            'num_root': np.zeros(n_dos),
            'num_file_creations': np.zeros(n_dos),
            'num_shells': np.zeros(n_dos),
            'num_access_files': np.zeros(n_dos),
            'num_outbound_cmds': np.zeros(n_dos),
            'is_host_login': np.zeros(n_dos),
            'is_guest_login': np.zeros(n_dos),
            'count': np.random.randint(200, 500, n_dos),
            'srv_count': np.random.randint(200, 500, n_dos),
            'serror_rate': np.random.uniform(0.5, 1.0, n_dos),
            'srv_serror_rate': np.random.uniform(0.5, 1.0, n_dos),
            'rerror_rate': np.random.uniform(0, 0.3, n_dos),
            'srv_rerror_rate': np.random.uniform(0, 0.3, n_dos),
            'same_srv_rate': np.random.uniform(0.8, 1.0, n_dos),
            'diff_srv_rate': np.random.uniform(0, 0.2, n_dos),
            'srv_diff_host_rate': np.random.uniform(0, 0.1, n_dos),
            'dst_host_count': np.random.randint(100, 255, n_dos),
            'dst_host_srv_count': np.random.randint(100, 255, n_dos),
            'dst_host_same_srv_rate': np.random.uniform(0.9, 1.0, n_dos),
            'dst_host_diff_srv_rate': np.random.uniform(0, 0.1, n_dos),
            'dst_host_same_src_port_rate': np.random.uniform(0.3, 0.7, n_dos),
            'dst_host_srv_diff_host_rate': np.random.uniform(0, 0.1, n_dos),
            'dst_host_serror_rate': np.random.uniform(0.5, 1.0, n_dos),
            'dst_host_srv_serror_rate': np.random.uniform(0.5, 1.0, n_dos),
            'dst_host_rerror_rate': np.random.uniform(0, 0.3, n_dos),
            'dst_host_srv_rerror_rate': np.random.uniform(0, 0.3, n_dos),
            'label': np.random.choice(['dos', 'neptune', 'smurf', 'pod'], n_dos),
            'difficulty': np.ones(n_dos)
        }

        # Generate Probe attacks (10%)
        n_probe = int(n_samples * 0.10)
        probe_data = {
            'duration': np.random.exponential(1, n_probe),
            'protocol_type': np.random.choice(['tcp', 'udp', 'icmp'], n_probe),
            'service': np.random.choice(['http', 'ftp', 'smtp', 'ssh', 'telnet'], n_probe),
            'flag': np.random.choice(['SF', 'S0', 'REJ', 'RSTO'], n_probe, p=[0.2, 0.5, 0.2, 0.1]),
            'src_bytes': np.random.lognormal(4, 1, n_probe).astype(int),
            'dst_bytes': np.random.lognormal(3, 1, n_probe).astype(int),
            'land': np.zeros(n_probe),
            'wrong_fragment': np.random.poisson(0.2, n_probe),
            'urgent': np.zeros(n_probe),
            'hot': np.random.poisson(0.3, n_probe),
            'num_failed_logins': np.zeros(n_probe),
            'logged_in': np.zeros(n_probe),
            'num_compromised': np.zeros(n_probe),
            'root_shell': np.zeros(n_probe),
            'su_attempted': np.zeros(n_probe),
            'num_root': np.zeros(n_probe),
            'num_file_creations': np.zeros(n_probe),
            'num_shells': np.zeros(n_probe),
            'num_access_files': np.zeros(n_probe),
            'num_outbound_cmds': np.zeros(n_probe),
            'is_host_login': np.zeros(n_probe),
            'is_guest_login': np.zeros(n_probe),
            'count': np.random.randint(50, 200, n_probe),
            'srv_count': np.random.randint(10, 100, n_probe),
            'serror_rate': np.random.uniform(0.3, 0.8, n_probe),
            'srv_serror_rate': np.random.uniform(0.3, 0.8, n_probe),
            'rerror_rate': np.random.uniform(0.2, 0.6, n_probe),
            'srv_rerror_rate': np.random.uniform(0.2, 0.6, n_probe),
            'same_srv_rate': np.random.uniform(0, 0.5, n_probe),
            'diff_srv_rate': np.random.uniform(0.5, 1.0, n_probe),
            'srv_diff_host_rate': np.random.uniform(0.5, 1.0, n_probe),
            'dst_host_count': np.random.randint(50, 255, n_probe),
            'dst_host_srv_count': np.random.randint(10, 100, n_probe),
            'dst_host_same_srv_rate': np.random.uniform(0, 0.5, n_probe),
            'dst_host_diff_srv_rate': np.random.uniform(0.5, 1.0, n_probe),
            'dst_host_same_src_port_rate': np.random.uniform(0, 0.3, n_probe),
            'dst_host_srv_diff_host_rate': np.random.uniform(0.5, 1.0, n_probe),
            'dst_host_serror_rate': np.random.uniform(0.3, 0.8, n_probe),
            'dst_host_srv_serror_rate': np.random.uniform(0.3, 0.8, n_probe),
            'dst_host_rerror_rate': np.random.uniform(0.2, 0.6, n_probe),
            'dst_host_srv_rerror_rate': np.random.uniform(0.2, 0.6, n_probe),
            'label': np.random.choice(['portsweep', 'ipsweep', 'nmap', 'satan'], n_probe),
            'difficulty': np.ones(n_probe)
        }

        # Generate R2L attacks (3%)
        n_r2l = int(n_samples * 0.03)
        r2l_data = {
            'duration': np.random.exponential(3, n_r2l),
            'protocol_type': np.random.choice(['tcp', 'udp'], n_r2l, p=[0.8, 0.2]),
            'service': np.random.choice(['ftp', 'telnet', 'ssh', 'http'], n_r2l),
            'flag': np.random.choice(['SF', 'S0', 'REJ'], n_r2l, p=[0.5, 0.3, 0.2]),
            'src_bytes': np.random.lognormal(6, 2, n_r2l).astype(int),
            'dst_bytes': np.random.lognormal(7, 2, n_r2l).astype(int),
            'land': np.zeros(n_r2l),
            'wrong_fragment': np.random.poisson(0.1, n_r2l),
            'urgent': np.zeros(n_r2l),
            'hot': np.random.poisson(1.5, n_r2l),
            'num_failed_logins': np.random.poisson(3, n_r2l),
            'logged_in': np.random.choice([0, 1], n_r2l, p=[0.7, 0.3]),
            'num_compromised': np.random.poisson(0.5, n_r2l),
            'root_shell': np.random.choice([0, 1], n_r2l, p=[0.9, 0.1]),
            'su_attempted': np.random.choice([0, 1], n_r2l, p=[0.95, 0.05]),
            'num_root': np.random.poisson(0.3, n_r2l),
            'num_file_creations': np.random.poisson(2, n_r2l),
            'num_shells': np.random.choice([0, 1], n_r2l, p=[0.9, 0.1]),
            'num_access_files': np.random.poisson(1.5, n_r2l),
            'num_outbound_cmds': np.zeros(n_r2l),
            'is_host_login': np.zeros(n_r2l),
            'is_guest_login': np.random.choice([0, 1], n_r2l, p=[0.8, 0.2]),
            'count': np.random.randint(1, 50, n_r2l),
            'srv_count': np.random.randint(1, 50, n_r2l),
            'serror_rate': np.random.uniform(0, 0.3, n_r2l),
            'srv_serror_rate': np.random.uniform(0, 0.3, n_r2l),
            'rerror_rate': np.random.uniform(0.3, 0.7, n_r2l),
            'srv_rerror_rate': np.random.uniform(0.3, 0.7, n_r2l),
            'same_srv_rate': np.random.uniform(0.5, 1.0, n_r2l),
            'diff_srv_rate': np.random.uniform(0, 0.5, n_r2l),
            'srv_diff_host_rate': np.random.uniform(0, 0.3, n_r2l),
            'dst_host_count': np.random.randint(1, 100, n_r2l),
            'dst_host_srv_count': np.random.randint(1, 100, n_r2l),
            'dst_host_same_srv_rate': np.random.uniform(0.5, 1.0, n_r2l),
            'dst_host_diff_srv_rate': np.random.uniform(0, 0.5, n_r2l),
            'dst_host_same_src_port_rate': np.random.uniform(0.3, 0.8, n_r2l),
            'dst_host_srv_diff_host_rate': np.random.uniform(0, 0.3, n_r2l),
            'dst_host_serror_rate': np.random.uniform(0, 0.3, n_r2l),
            'dst_host_srv_serror_rate': np.random.uniform(0, 0.3, n_r2l),
            'dst_host_rerror_rate': np.random.uniform(0.3, 0.7, n_r2l),
            'dst_host_srv_rerror_rate': np.random.uniform(0.3, 0.7, n_r2l),
            'label': np.random.choice(['ftp_write', 'guess_passwd', 'warezmaster', 'imap'], n_r2l),
            'difficulty': np.ones(n_r2l) * 2
        }

        # Generate U2R attacks (2%)
        n_u2r = n_samples - n_normal - n_dos - n_probe - n_r2l
        u2r_data = {
            'duration': np.random.exponential(5, n_u2r),
            'protocol_type': np.random.choice(['tcp'], n_u2r),
            'service': np.random.choice(['ftp', 'telnet', 'ssh'], n_u2r),
            'flag': np.random.choice(['SF', 'S0'], n_u2r, p=[0.7, 0.3]),
            'src_bytes': np.random.lognormal(8, 2, n_u2r).astype(int),
            'dst_bytes': np.random.lognormal(9, 2, n_u2r).astype(int),
            'land': np.zeros(n_u2r),
            'wrong_fragment': np.zeros(n_u2r),
            'urgent': np.zeros(n_u2r),
            'hot': np.random.poisson(5, n_u2r),
            'num_failed_logins': np.random.poisson(1, n_u2r),
            'logged_in': np.ones(n_u2r),
            'num_compromised': np.random.poisson(2, n_u2r),
            'root_shell': np.random.choice([0, 1], n_u2r, p=[0.3, 0.7]),
            'su_attempted': np.random.choice([0, 1, 2], n_u2r, p=[0.3, 0.5, 0.2]),
            'num_root': np.random.poisson(3, n_u2r),
            'num_file_creations': np.random.poisson(5, n_u2r),
            'num_shells': np.random.choice([0, 1, 2], n_u2r, p=[0.3, 0.5, 0.2]),
            'num_access_files': np.random.poisson(3, n_u2r),
            'num_outbound_cmds': np.zeros(n_u2r),
            'is_host_login': np.zeros(n_u2r),
            'is_guest_login': np.zeros(n_u2r),
            'count': np.random.randint(1, 20, n_u2r),
            'srv_count': np.random.randint(1, 20, n_u2r),
            'serror_rate': np.random.uniform(0, 0.2, n_u2r),
            'srv_serror_rate': np.random.uniform(0, 0.2, n_u2r),
            'rerror_rate': np.random.uniform(0, 0.2, n_u2r),
            'srv_rerror_rate': np.random.uniform(0, 0.2, n_u2r),
            'same_srv_rate': np.random.uniform(0.7, 1.0, n_u2r),
            'diff_srv_rate': np.random.uniform(0, 0.3, n_u2r),
            'srv_diff_host_rate': np.random.uniform(0, 0.2, n_u2r),
            'dst_host_count': np.random.randint(1, 50, n_u2r),
            'dst_host_srv_count': np.random.randint(1, 50, n_u2r),
            'dst_host_same_srv_rate': np.random.uniform(0.7, 1.0, n_u2r),
            'dst_host_diff_srv_rate': np.random.uniform(0, 0.3, n_u2r),
            'dst_host_same_src_port_rate': np.random.uniform(0.5, 1.0, n_u2r),
            'dst_host_srv_diff_host_rate': np.random.uniform(0, 0.2, n_u2r),
            'dst_host_serror_rate': np.random.uniform(0, 0.2, n_u2r),
            'dst_host_srv_serror_rate': np.random.uniform(0, 0.2, n_u2r),
            'dst_host_rerror_rate': np.random.uniform(0, 0.2, n_u2r),
            'dst_host_srv_rerror_rate': np.random.uniform(0, 0.2, n_u2r),
            'label': np.random.choice(['buffer_overflow', 'rootkit', 'loadmodule', 'perl'], n_u2r),
            'difficulty': np.ones(n_u2r) * 3
        }

        # Combine all data
        all_data = []
        for data_dict in [normal_data, dos_data, probe_data, r2l_data, u2r_data]:
            all_data.append(pd.DataFrame(data_dict))

        df = pd.concat(all_data, ignore_index=True)

        # Shuffle the dataset
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)

        return df

    def preprocess_data(self, df):
        """Preprocess the dataset"""
        # Separate features and labels
        X = df.drop(['label', 'difficulty'], axis=1)
        y = df['label']

        # Create binary classification (normal vs attack)
        y_binary = (y != 'normal').astype(int)

        # Encode categorical features
        categorical_cols = ['protocol_type', 'service', 'flag']

        for col in categorical_cols:
            if col == 'protocol_type':
                X[col] = self.protocol_encoder.fit_transform(X[col])
            elif col == 'service':
                X[col] = self.service_encoder.fit_transform(X[col])
            elif col == 'flag':
                X[col] = self.flag_encoder.fit_transform(X[col])

        # Store feature names
        self.feature_names = X.columns.tolist()

        # Scale numerical features
        X_scaled = self.scaler.fit_transform(X)

        return X_scaled, y_binary, y

    def split_data(self, X, y, test_size=0.2, val_size=0.1):
        """Split data into train, validation, and test sets"""
        # First split: train+val vs test
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )

        # Second split: train vs val
        val_ratio = val_size / (1 - test_size)
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp, test_size=val_ratio, random_state=42, stratify=y_temp
        )

        return X_train, X_val, X_test, y_train, y_val, y_test

    def save_preprocessors(self, save_dir='../models'):
        """Save preprocessing objects"""
        os.makedirs(save_dir, exist_ok=True)

        with open(f'{save_dir}/scaler.pkl', 'wb') as f:
            pickle.dump(self.scaler, f)

        with open(f'{save_dir}/protocol_encoder.pkl', 'wb') as f:
            pickle.dump(self.protocol_encoder, f)

        with open(f'{save_dir}/service_encoder.pkl', 'wb') as f:
            pickle.dump(self.service_encoder, f)

        with open(f'{save_dir}/flag_encoder.pkl', 'wb') as f:
            pickle.dump(self.flag_encoder, f)

        with open(f'{save_dir}/feature_names.pkl', 'wb') as f:
            pickle.dump(self.feature_names, f)

    def load_preprocessors(self, save_dir='../models'):
        """Load preprocessing objects"""
        with open(f'{save_dir}/scaler.pkl', 'rb') as f:
            self.scaler = pickle.load(f)

        with open(f'{save_dir}/protocol_encoder.pkl', 'rb') as f:
            self.protocol_encoder = pickle.load(f)

        with open(f'{save_dir}/service_encoder.pkl', 'rb') as f:
            self.service_encoder = pickle.load(f)

        with open(f'{save_dir}/flag_encoder.pkl', 'rb') as f:
            self.flag_encoder = pickle.load(f)

        with open(f'{save_dir}/feature_names.pkl', 'rb') as f:
            self.feature_names = pickle.load(f)


if __name__ == "__main__":
    # Test the data loader
    loader = IDSDataLoader()

    print("Creating sample network traffic data...")
    df = loader.create_sample_data(n_samples=10000)

    print(f"\nDataset shape: {df.shape}")
    print(f"\nLabel distribution:\n{df['label'].value_counts()}")
    print(f"\nFirst few rows:\n{df.head()}")

    print("\nPreprocessing data...")
    X, y_binary, y_multi = loader.preprocess_data(df)

    print(f"\nProcessed features shape: {X.shape}")
    print(f"Binary labels (normal=0, attack=1): {np.bincount(y_binary)}")

    print("\nSplitting data...")
    X_train, X_val, X_test, y_train, y_val, y_test = loader.split_data(X, y_binary)

    print(f"Train set: {X_train.shape}")
    print(f"Validation set: {X_val.shape}")
    print(f"Test set: {X_test.shape}")

    # Save sample data
    os.makedirs('../data', exist_ok=True)
    df.to_csv('../data/sample_network_traffic.csv', index=False)
    print("\nSample data saved to ../data/sample_network_traffic.csv")
