from scapy.all import sniff, IP, TCP, UDP, ICMP
from realtime_detection import RealTimeIDS
from collections import defaultdict
import time


class RealPacketCapture:
    def __init__(self):
        self.ids = RealTimeIDS()
        self.connection_stats = defaultdict(lambda: {
            'count': 0,
            's`rc_bytes': 0,
            'dst_bytes': 0,
            'start_time': time.time()
        })

    def packet_to_features(self, packet):
        """Convert real packet to feature format"""

        if not packet.haslayer(IP):
            return None

        # Extract basic info
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Determine protocol
        if packet.haslayer(TCP):
            protocol = 'tcp'
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
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

        # Determine service based on port
        service_map = {
            80: 'http', 443: 'http', 21: 'ftp',
            22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 110: 'pop3'
        }
        service = service_map.get(dst_port, 'other')

        # Get packet size
        packet_size = len(packet)

        # Build connection key
        conn_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"

        # Update connection stats
        stats = self.connection_stats[conn_key]
        stats['count'] += 1
        stats['src_bytes'] += packet_size
        duration = time.time() - stats['start_time']

        # Create feature dict (simplified - you'd need all 41 features)
        features = {
            'duration': duration,
            'protocol_type': protocol,
            'service': service,
            'flag': str(flags),
            'src_bytes': stats['src_bytes'],
            'dst_bytes': stats.get('dst_bytes', 0),
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

    def analyze_packet(self, packet):
        """Analyze a captured packet"""
        features = self.packet_to_features(packet)

        if features:
            result = self.ids.detect(features)

            if result['is_attack']:
                print("🚨 ATTACK DETECTED!")
                print(f"   Time: {result['timestamp']}")
                print(f"   Confidence: {result['confidence']:.2%}")
                print(f"   Packet: {packet.summary()}")
                print()

    def start_monitoring(self, interface=None, count=100):
        """Start capturing real network traffic"""
        print("Starting real network monitoring...")
        print(f"Interface: {interface or 'default'}")
        print(f"Packets to capture: {count}")
        print("-" * 60)

        # Start sniffing
        # NOTE: May require admin/root privileges
        sniff(iface=interface, prn=self.analyze_packet, count=count)


if __name__ == "__main__":
    capturer = RealPacketCapture()

    # Monitor 100 packets on default interface
    # Windows: Use "Wi-Fi" or "Ethernet"
    # Linux: Use "eth0", "wlan0", etc.
    capturer.start_monitoring(interface=None, count=100)
