"""
Simple script to capture network traffic to a PCAP file
"""

from scapy.all import sniff
from scapy.utils import wrpcap
import os


def capture_traffic(filename="capture.pcap", count=100, timeout=100):
    """
    Capture network traffic and save to PCAP file

    Args:
        filename: Output PCAP filename
        count: Number of packets to capture (default 1000)
        timeout: Max seconds to capture (default 120)
    """

    print("=" * 120)
    print("NETWORK TRAFFIC CAPTURE")
    print("=" * 120)
    print(f"\nCapturing to: {filename}")
    print(f"Packets to capture: {count}")
    print(f"Timeout: {timeout} seconds")
    print("\nCapturing... (Press Ctrl+C to stop early)\n")

    try:
        # Capture packets
        packets = sniff(count=count, timeout=timeout)

        # Save to file
        wrpcap(filename, packets)

        print(f"\n✅ Captured {len(packets)} packets")
        print(f"✅ Saved to: {os.path.abspath(filename)}")
        print("\nYou can now analyze this file with:")
        print(f"  python analyze_pcap.py {filename}")

    except KeyboardInterrupt:
        print("\n\nCapture stopped by user")
        if 'packets' in locals() and len(packets) > 0:
            wrpcap(filename, packets)
            print(f"✅ Saved {len(packets)} packets to: {filename}")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\nTry running as Administrator if you haven't already!")


if __name__ == "__main__":
    import sys

    # Get filename from command line or use default
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    else:
        filename = "my_capture.pcap"

    # Capture 200 packets or for 60 seconds, whichever comes first
    capture_traffic(filename=filename, count=100000, timeout=10000)
