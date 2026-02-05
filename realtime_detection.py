"""
Real-time Intrusion Detection System
Monitors network traffic and detects attacks in real-time
"""

import numpy as np
import pandas as pd
import joblib
import pickle
from datetime import datetime
import json
import time
from collections import deque


class RealTimeIDS:
    """Real-time intrusion detection system"""

    def __init__(self, model_path='../models/best_ids_model.pkl',
                 preprocessor_dir='../models'):
        """Initialize the IDS with trained model and preprocessors"""
        print("Initializing Real-Time IDS...")

        # Load model
        self.model = joblib.load(model_path)
        print(f"✓ Loaded trained model from {model_path}")

        # Load preprocessors
        with open(f'{preprocessor_dir}/scaler.pkl', 'rb') as f:
            self.scaler = pickle.load(f)

        with open(f'{preprocessor_dir}/protocol_encoder.pkl', 'rb') as f:
            self.protocol_encoder = pickle.load(f)

        with open(f'{preprocessor_dir}/service_encoder.pkl', 'rb') as f:
            self.service_encoder = pickle.load(f)

        with open(f'{preprocessor_dir}/flag_encoder.pkl', 'rb') as f:
            self.flag_encoder = pickle.load(f)

        with open(f'{preprocessor_dir}/feature_names.pkl', 'rb') as f:
            self.feature_names = pickle.load(f)

        print("✓ Loaded preprocessors")

        # Detection stats
        self.total_packets = 0
        self.attacks_detected = 0
        self.attack_history = deque(maxlen=100)  # Keep last 100 detections
        self.start_time = datetime.now()

        print("\n" + "=" * 60)
        print("Real-Time IDS Ready!")
        print("=" * 60 + "\n")

    def preprocess_packet(self, packet_data):
        """Preprocess a single packet for prediction"""
        # Create DataFrame from packet data
        df = pd.DataFrame([packet_data])

        # Encode categorical features
        if 'protocol_type' in df.columns:
            try:
                df['protocol_type'] = self.protocol_encoder.transform(df['protocol_type'])
            except (ValueError, KeyError):
                df['protocol_type'] = 0  # Unknown protocol

        if 'service' in df.columns:
            try:
                df['service'] = self.service_encoder.transform(df['service'])
            except (ValueError, KeyError):
                df['service'] = 0  # Unknown service

        if 'flag' in df.columns:
            try:
                df['flag'] = self.flag_encoder.transform(df['flag'])
            except (ValueError, KeyError):
                df['flag'] = 0  # Unknown flag

        # Ensure all features are present
        for feature in self.feature_names:
            if feature not in df.columns:
                df[feature] = 0

        # Select and order features
        df = df[self.feature_names]

        # Scale features
        X = self.scaler.transform(df)

        return X

    def detect(self, packet_data):
        """Detect if a packet is an attack"""
        # Preprocess packet
        X = self.preprocess_packet(packet_data)

        # Make prediction
        prediction = self.model.predict(X)[0]

        # Try to get prediction probability
        try:
            probability = self.model.predict_proba(X)[0]
            confidence = probability[prediction]
        except AttributeError:
            confidence = None

        # Update statistics
        self.total_packets += 1

        # Create detection result
        result = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'is_attack': bool(prediction),
            'confidence': float(confidence) if confidence is not None else None,
            'packet_number': self.total_packets,
            'packet_data': packet_data
        }

        if prediction == 1:  # Attack detected
            self.attacks_detected += 1
            self.attack_history.append(result)

        return result

    def monitor_traffic(self, traffic_generator, duration=60, alert_callback=None):
        """
        Monitor network traffic for a specified duration

        Args:
            traffic_generator: Generator that yields packet data dictionaries
            duration: How long to monitor (in seconds)
            alert_callback: Optional function to call when attack is detected
        """
        print(f"Starting traffic monitoring for {duration} seconds...")
        print(f"{'='*60}\n")

        start_time = time.time()

        while (time.time() - start_time) < duration:
            try:
                # Get next packet
                packet = next(traffic_generator)

                # Detect intrusion
                result = self.detect(packet)

                # Display result
                status = "🚨 ATTACK" if result['is_attack'] else "✓ Normal"
                conf_str = f" (confidence: {result['confidence']:.2%})" if result['confidence'] else ""

                print(f"[{result['timestamp']}] Packet #{result['packet_number']:5d} | {status}{conf_str}")

                # Call alert callback if attack detected
                if result['is_attack'] and alert_callback:
                    alert_callback(result)

                # Small delay to make output readable
                time.sleep(0.1)

            except StopIteration:
                print("\nTraffic generator exhausted")
                break
            except KeyboardInterrupt:
                print("\n\nMonitoring stopped by user")
                break

        self.print_summary()

    def print_summary(self):
        """Print detection summary statistics"""
        elapsed = (datetime.now() - self.start_time).total_seconds()

        print("\n" + "=" * 60)
        print("DETECTION SUMMARY")
        print("=" * 60)
        print(f"Total Packets Analyzed: {self.total_packets}")
        print(f"Attacks Detected: {self.attacks_detected}")
        print(f"Attack Rate: {(self.attacks_detected/self.total_packets*100):.2f}%" if self.total_packets > 0 else "N/A")
        print(f"Monitoring Duration: {elapsed:.2f} seconds")
        print(f"Packets/Second: {self.total_packets/elapsed:.2f}" if elapsed > 0 else "N/A")
        print("=" * 60 + "\n")

    def get_recent_attacks(self, n=10):
        """Get the n most recent attacks detected"""
        return list(self.attack_history)[-n:]

    def save_attack_log(self, filepath='../logs/attack_log.json'):
        """Save attack history to file"""
        import os
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        with open(filepath, 'w') as f:
            json.dump(list(self.attack_history), f, indent=2)
        print(f"Attack log saved to {filepath}")


def generate_sample_traffic(n_packets=100, attack_rate=0.2):
    """
    Generate sample network traffic for testing

    Args:
        n_packets: Number of packets to generate
        attack_rate: Probability of generating an attack packet
    """
    np.random.seed(int(time.time()))

    for i in range(n_packets):
        is_attack = np.random.random() < attack_rate

        if is_attack:
            # Generate attack-like traffic
            packet = {
                'duration': np.random.exponential(0.5),
                'protocol_type': np.random.choice(['tcp', 'udp', 'icmp']),
                'service': np.random.choice(['http', 'ftp', 'smtp']),
                'flag': np.random.choice(['S0', 'REJ', 'RSTO']),
                'src_bytes': int(np.random.lognormal(5, 1.5)),
                'dst_bytes': int(np.random.lognormal(4, 1)),
                'land': 0,
                'wrong_fragment': int(np.random.poisson(0.3)),
                'urgent': int(np.random.poisson(0.5)),
                'hot': int(np.random.poisson(2)),
                'num_failed_logins': 0,
                'logged_in': 0,
                'num_compromised': 0,
                'root_shell': 0,
                'su_attempted': 0,
                'num_root': 0,
                'num_file_creations': 0,
                'num_shells': 0,
                'num_access_files': 0,
                'num_outbound_cmds': 0,
                'is_host_login': 0,
                'is_guest_login': 0,
                'count': int(np.random.randint(200, 500)),
                'srv_count': int(np.random.randint(200, 500)),
                'serror_rate': float(np.random.uniform(0.5, 1.0)),
                'srv_serror_rate': float(np.random.uniform(0.5, 1.0)),
                'rerror_rate': float(np.random.uniform(0, 0.3)),
                'srv_rerror_rate': float(np.random.uniform(0, 0.3)),
                'same_srv_rate': float(np.random.uniform(0.8, 1.0)),
                'diff_srv_rate': float(np.random.uniform(0, 0.2)),
                'srv_diff_host_rate': float(np.random.uniform(0, 0.1)),
                'dst_host_count': int(np.random.randint(100, 255)),
                'dst_host_srv_count': int(np.random.randint(100, 255)),
                'dst_host_same_srv_rate': float(np.random.uniform(0.9, 1.0)),
                'dst_host_diff_srv_rate': float(np.random.uniform(0, 0.1)),
                'dst_host_same_src_port_rate': float(np.random.uniform(0.3, 0.7)),
                'dst_host_srv_diff_host_rate': float(np.random.uniform(0, 0.1)),
                'dst_host_serror_rate': float(np.random.uniform(0.5, 1.0)),
                'dst_host_srv_serror_rate': float(np.random.uniform(0.5, 1.0)),
                'dst_host_rerror_rate': float(np.random.uniform(0, 0.3)),
                'dst_host_srv_rerror_rate': float(np.random.uniform(0, 0.3)),
            }
        else:
            # Generate normal traffic
            packet = {
                'duration': np.random.exponential(2),
                'protocol_type': np.random.choice(['tcp', 'udp', 'icmp']),
                'service': np.random.choice(['http', 'ftp', 'smtp', 'ssh', 'dns']),
                'flag': np.random.choice(['SF', 'S0', 'REJ']),
                'src_bytes': int(np.random.lognormal(7, 2)),
                'dst_bytes': int(np.random.lognormal(8, 2)),
                'land': 0,
                'wrong_fragment': int(np.random.poisson(0.1)),
                'urgent': 0,
                'hot': int(np.random.poisson(0.5)),
                'num_failed_logins': 0,
                'logged_in': 1,
                'num_compromised': 0,
                'root_shell': 0,
                'su_attempted': 0,
                'num_root': int(np.random.poisson(0.2)),
                'num_file_creations': int(np.random.poisson(1)),
                'num_shells': 0,
                'num_access_files': int(np.random.poisson(0.5)),
                'num_outbound_cmds': 0,
                'is_host_login': 0,
                'is_guest_login': 0,
                'count': int(np.random.randint(1, 100)),
                'srv_count': int(np.random.randint(1, 100)),
                'serror_rate': float(np.random.uniform(0, 0.2)),
                'srv_serror_rate': float(np.random.uniform(0, 0.2)),
                'rerror_rate': float(np.random.uniform(0, 0.2)),
                'srv_rerror_rate': float(np.random.uniform(0, 0.2)),
                'same_srv_rate': float(np.random.uniform(0.7, 1.0)),
                'diff_srv_rate': float(np.random.uniform(0, 0.3)),
                'srv_diff_host_rate': float(np.random.uniform(0, 0.3)),
                'dst_host_count': int(np.random.randint(1, 255)),
                'dst_host_srv_count': int(np.random.randint(1, 255)),
                'dst_host_same_srv_rate': float(np.random.uniform(0.7, 1.0)),
                'dst_host_diff_srv_rate': float(np.random.uniform(0, 0.3)),
                'dst_host_same_src_port_rate': float(np.random.uniform(0.5, 1.0)),
                'dst_host_srv_diff_host_rate': float(np.random.uniform(0, 0.3)),
                'dst_host_serror_rate': float(np.random.uniform(0, 0.2)),
                'dst_host_srv_serror_rate': float(np.random.uniform(0, 0.2)),
                'dst_host_rerror_rate': float(np.random.uniform(0, 0.2)),
                'dst_host_srv_rerror_rate': float(np.random.uniform(0, 0.2)),
            }

        yield packet


def alert_handler(result):
    """Handle attack detection alerts"""
    print(f"\n{'!'*60}")
    print(f"ALERT: Attack detected at {result['timestamp']}")
    print(f"Packet #{result['packet_number']}")
    if result['confidence']:
        print(f"Confidence: {result['confidence']:.2%}")
    print(f"{'!'*60}\n")


def main():
    """Main function for real-time detection demo"""
    print("\n" + "=" * 60)
    print("REAL-TIME INTRUSION DETECTION SYSTEM - DEMO")
    print("=" * 60 + "\n")

    # Initialize IDS
    ids = RealTimeIDS(
        model_path='../models/best_ids_model.pkl',
        preprocessor_dir='../models'
    )

    # Generate sample traffic
    print("Generating sample network traffic...")
    traffic = generate_sample_traffic(n_packets=100, attack_rate=0.25)

    # Monitor traffic
    print("\nStarting real-time monitoring...\n")
    ids.monitor_traffic(traffic, duration=30, alert_callback=alert_handler)

    # Show recent attacks
    print("\nRecent Attacks Detected:")
    recent = ids.get_recent_attacks(n=5)
    for i, attack in enumerate(recent, 1):
        print(f"{i}. {attack['timestamp']} - Packet #{attack['packet_number']}")

    # Save attack log
    ids.save_attack_log('../logs/attack_log.json')

    print("\nComplete!")


if __name__ == "__main__":
    main()
