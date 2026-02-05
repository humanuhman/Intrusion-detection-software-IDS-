"""
Analyze PCAP files for network intrusions
"""

from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from realtime_detection import RealTimeIDS
from collections import defaultdict
import time


class PCAPAnalyzer:
    def __init__(self):
        self.ids = RealTimeIDS()
        self.connection_stats = defaultdict(lambda: {
            'count': 0,
            'src_bytes': 0,
            'start_time': 0
        })

    def packet_to_features(self, packet):
        """Convert a network packet to feature format for IDS"""

        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        packet_size = len(packet)

        # Determine protocol and ports
        if packet.haslayer(TCP):
            protocol = 'tcp'
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = str(packet[TCP].flags)
        elif packet.haslayer(UDP):
            protocol = 'udp'
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            flags = 'SF'
        elif packet.haslayer(ICMP):
            protocol = 'icmp'
            src_port = 0
            dst_port = 0
            flags = 'SF'
        else:
            return None

        # Map port to service
        service_map = {
            80: 'http', 443: 'http', 8080: 'http',
            21: 'ftp', 22: 'ssh', 23: 'telnet',
            25: 'smtp', 53: 'dns', 110: 'pop3',
            143: 'imap', 3306: 'mysql', 5432: 'postgresql'
        }
        service = service_map.get(dst_port, 'other')

        # Track connection
        conn_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        stats = self.connection_stats[conn_key]

        if stats['start_time'] == 0:
            stats['start_time'] = time.time()

        stats['count'] += 1
        stats['src_bytes'] += packet_size

        duration = time.time() - stats['start_time']

        # Build feature dictionary (simplified version)
        features = {
            'duration': duration if duration > 0 else 0.1,
            'protocol_type': protocol,
            'service': service,
            'flag': flags[:4] if len(flags) > 4 else flags,
            'src_bytes': stats['src_bytes'],
            'dst_bytes': packet_size,
            'land': 1 if src_ip == dst_ip else 0,
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': 1,
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
            'count': stats['count'],
            'srv_count': stats['count'],
            'serror_rate': 0.0,
            'srv_serror_rate': 0.0,
            'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0,
            'same_srv_rate': 0.8,
            'diff_srv_rate': 0.2,
            'srv_diff_host_rate': 0.1,
            'dst_host_count': 10,
            'dst_host_srv_count': 10,
            'dst_host_same_srv_rate': 0.8,
            'dst_host_diff_srv_rate': 0.2,
            'dst_host_same_src_port_rate': 0.5,
            'dst_host_srv_diff_host_rate': 0.1,
            'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0,
            'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0,
        }

        return features

    def analyze_pcap(self, filename):
        """Analyze a PCAP file for intrusions"""

        print("\n" + "=" * 60)
        print("PCAP FILE ANALYSIS")
        print("=" * 60)
        print(f"\nFile: {filename}")

        try:
            print("Loading packets...")
            packets = rdpcap(filename)
            print(f"Total packets: {len(packets)}")
            print("\nAnalyzing...\n")

            attack_count = 0
            normal_count = 0
            skipped_count = 0

            for i, packet in enumerate(packets, 1):
                features = self.packet_to_features(packet)

                if features is None:
                    skipped_count += 1
                    continue

                result = self.ids.detect(features)

                if result['is_attack']:
                    attack_count += 1
                    print(f"🚨 Packet #{i}: ATTACK DETECTED")
                    print(f"   Confidence: {result['confidence']:.2%}")
                    print(f"   Summary: {packet.summary()}")
                    print()
                else:
                    normal_count += 1
                    if normal_count % 50 == 0:  # Print progress
                        print(f"✓ Analyzed {normal_count} normal packets...")

            # Summary
            print("\n" + "=" * 60)
            print("ANALYSIS SUMMARY")
            print("=" * 60)
            print(f"Total Packets: {len(packets)}")
            print(f"Analyzed: {normal_count + attack_count}")
            print(f"Skipped (non-IP): {skipped_count}")
            print(f"\n✅ Normal Traffic: {normal_count}")
            print(f"🚨 Attacks Detected: {attack_count}")

            if attack_count + normal_count > 0:
                attack_rate = (attack_count / (attack_count + normal_count)) * 100
                print(f"📊 Attack Rate: {attack_rate:.2f}%")

            print("=" * 60 + "\n")

        except FileNotFoundError:
            print(f"\n❌ Error: File '{filename}' not found!")
            print("Make sure the file is in the correct location.\n")
        except Exception as e:
            print(f"\n❌ Error analyzing file: {e}\n")


def main():
    import sys

    analyzer = PCAPAnalyzer()

    # Get filename from command line or use default
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    else:
        filename = input("Enter PCAP filename (or path): ")

    analyzer.analyze_pcap(filename)


if __name__ == "__main__":
    main()
