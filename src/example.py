#!/usr/bin/env python3
"""
Quick Start Example for Intrusion Detection System
This script demonstrates basic usage of the IDS
"""

from realtime_detection import RealTimeIDS, generate_sample_traffic
import time


def simple_detection_demo():
    """Simple demonstration of packet-by-packet detection"""
    print("\n" + "=" * 60)
    print("SIMPLE IDS DETECTION DEMO")
    print("=" * 60 + "\n")

    # Initialize IDS
    print("Loading IDS...")
    ids = RealTimeIDS(
        model_path='../models/best_ids_model.pkl',
        preprocessor_dir='../models'
    )

    # Analyze 10 sample packets
    print("\nAnalyzing 10 sample network packets...\n")
    traffic = generate_sample_traffic(n_packets=10, attack_rate=0.3)

    for i, packet in enumerate(traffic, 1):
        result = ids.detect(packet)

        status = "🚨 ATTACK DETECTED" if result['is_attack'] else "✅ Normal Traffic"
        conf = f"{result['confidence']:.1%}" if result['confidence'] else "N/A"

        print(f"Packet {i:2d}: {status} (Confidence: {conf})")
        time.sleep(0.3)

    print("\n" + "=" * 60)
    print(f"Summary: {ids.attacks_detected}/{ids.total_packets} attacks detected")
    print("=" * 60 + "\n")


def batch_detection_demo():
    """Demonstrate analyzing a batch of packets"""
    print("\n" + "=" * 60)
    print("BATCH DETECTION DEMO")
    print("=" * 60 + "\n")

    # Initialize IDS
    ids = RealTimeIDS(
        model_path='../models/best_ids_model.pkl',
        preprocessor_dir='../models'
    )

    # Analyze 100 packets
    print("Analyzing 100 network packets...")
    traffic = generate_sample_traffic(n_packets=100, attack_rate=0.25)

    normal_count = 0
    attack_count = 0

    for packet in traffic:
        result = ids.detect(packet)
        if result['is_attack']:
            attack_count += 1
        else:
            normal_count += 1

    print(f"\n✅ Normal Traffic: {normal_count}")
    print(f"🚨 Attacks Detected: {attack_count}")
    print(f"📊 Attack Rate: {(attack_count/100)*100:.1f}%")
    print(f"\nProcessing Speed: {ids.total_packets/1:.0f} packets/second")


def custom_packet_demo():
    """Demonstrate detecting a custom packet"""
    print("\n" + "=" * 60)
    print("CUSTOM PACKET DETECTION DEMO")
    print("=" * 60 + "\n")

    # Initialize IDS
    ids = RealTimeIDS(
        model_path='../models/best_ids_model.pkl',
        preprocessor_dir='../models'
    )

    # Create a suspicious packet (DoS-like characteristics)
    suspicious_packet = {
        'duration': 0.1,
        'protocol_type': 'tcp',
        'service': 'http',
        'flag': 'S0',
        'src_bytes': 100,
        'dst_bytes': 50,
        'land': 0,
        'wrong_fragment': 0,
        'urgent': 1,
        'hot': 5,
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
        'count': 350,
        'srv_count': 400,
        'serror_rate': 0.85,
        'srv_serror_rate': 0.90,
        'rerror_rate': 0.1,
        'srv_rerror_rate': 0.1,
        'same_srv_rate': 0.95,
        'diff_srv_rate': 0.05,
        'srv_diff_host_rate': 0.02,
        'dst_host_count': 200,
        'dst_host_srv_count': 220,
        'dst_host_same_srv_rate': 0.98,
        'dst_host_diff_srv_rate': 0.02,
        'dst_host_same_src_port_rate': 0.4,
        'dst_host_srv_diff_host_rate': 0.01,
        'dst_host_serror_rate': 0.88,
        'dst_host_srv_serror_rate': 0.92,
        'dst_host_rerror_rate': 0.05,
        'dst_host_srv_rerror_rate': 0.05,
    }

    print("Analyzing custom packet with DoS-like characteristics...")
    result = ids.detect(suspicious_packet)

    print("\n📦 Packet Analysis:")
    print(f"   Protocol: {suspicious_packet['protocol_type']}")
    print(f"   Service: {suspicious_packet['service']}")
    print(f"   Connection Count: {suspicious_packet['count']}")
    print(f"   Error Rate: {suspicious_packet['serror_rate']:.1%}")

    print("\n🔍 Detection Result:")
    if result['is_attack']:
        print("   ⚠️  STATUS: ATTACK DETECTED")
    else:
        print("   ✅ STATUS: Normal Traffic")

    if result['confidence']:
        print(f"   📊 Confidence: {result['confidence']:.2%}")

    # Now analyze a normal packet
    normal_packet = {
        'duration': 2.5,
        'protocol_type': 'tcp',
        'service': 'http',
        'flag': 'SF',
        'src_bytes': 5000,
        'dst_bytes': 8000,
        'land': 0,
        'wrong_fragment': 0,
        'urgent': 0,
        'hot': 0,
        'num_failed_logins': 0,
        'logged_in': 1,
        'num_compromised': 0,
        'root_shell': 0,
        'su_attempted': 0,
        'num_root': 0,
        'num_file_creations': 1,
        'num_shells': 0,
        'num_access_files': 0,
        'num_outbound_cmds': 0,
        'is_host_login': 0,
        'is_guest_login': 0,
        'count': 15,
        'srv_count': 12,
        'serror_rate': 0.05,
        'srv_serror_rate': 0.03,
        'rerror_rate': 0.02,
        'srv_rerror_rate': 0.01,
        'same_srv_rate': 0.85,
        'diff_srv_rate': 0.15,
        'srv_diff_host_rate': 0.1,
        'dst_host_count': 50,
        'dst_host_srv_count': 45,
        'dst_host_same_srv_rate': 0.8,
        'dst_host_diff_srv_rate': 0.2,
        'dst_host_same_src_port_rate': 0.7,
        'dst_host_srv_diff_host_rate': 0.15,
        'dst_host_serror_rate': 0.04,
        'dst_host_srv_serror_rate': 0.02,
        'dst_host_rerror_rate': 0.03,
        'dst_host_srv_rerror_rate': 0.01,
    }

    print(f"\n{'─'*60}")
    print("Analyzing normal packet...")
    result = ids.detect(normal_packet)

    print("\n📦 Packet Analysis:")
    print(f"   Protocol: {normal_packet['protocol_type']}")
    print(f"   Service: {normal_packet['service']}")
    print(f"   Connection Count: {normal_packet['count']}")
    print(f"   Error Rate: {normal_packet['serror_rate']:.1%}")

    print("\n🔍 Detection Result:")
    if result['is_attack']:
        print("   ⚠️  STATUS: ATTACK DETECTED")
    else:
        print("   ✅ STATUS: Normal Traffic")

    if result['confidence']:
        print(f"   📊 Confidence: {result['confidence']:.2%}")


if __name__ == "__main__":
    # Run all demos
    simple_detection_demo()
    time.sleep(1)

    batch_detection_demo()
    time.sleep(1)

    custom_packet_demo()

    print("\n" + "=" * 60)
    print("All demos completed successfully!")
    print("=" * 60 + "\n")
