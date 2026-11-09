from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11ProbeResp
from scapy.layers.dot11 import Dot11Elt, RadioTap
import sys


def extract_network_information(packet):

    ssid = None
    channel = None
    signal_strength = None

    bssid = packet.addr3

    if packet.haslayer(Dot11Beacon):
        frame_type = "Beacon"

    elif packet.haslayer(Dot11ProbeResp):
        frame_type = "Probe Response"

    else:
        return None

    element = packet.getlayer(Dot11Elt)

    while isinstance(element, Dot11Elt):

        if element.ID == 0:
            ssid = element.info.decode(
                "utf-8", errors="replace"
            )

        elif element.ID == 3 and len(element.info) > 0:
            channel = element.info[0]

        element = element.payload

    if packet.haslayer(RadioTap):
        radiotap = packet.getlayer(RadioTap)

        if hasattr(radiotap, "dBm_AntSignal"):
            signal_strength = radiotap.dBm_AntSignal

    return {
        "SSID": ssid,
        "BSSID": bssid,
        "Channel": channel,
        "Signal Strength (dBm)": signal_strength,
        "Frame Type": frame_type
    }


def analyze_pcap(file_path):

    print("\nStarting wireless packet analysis...\n")

    packets = rdpcap(file_path)

    print(f"Total packets captured: {len(packets)}")

    detected_networks = []

    for packet in packets:

        if not packet.haslayer(Dot11):
            continue

        network = extract_network_information(packet)

        if network:
            detected_networks.append(network)

    print("\nWireless Management Frame Results")
    print("-" * 45)

    if not detected_networks:
        print("No supported wireless management frames found.")
        return

    for number, network in enumerate(detected_networks, start=1):

        print(f"\nNetwork Record {number}")

        for key, value in network.items():
            print(f"{key}: {value}")

    print("\nAnalysis completed.")
    print(f"Management frames analyzed: {len(detected_networks)}")


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: python packet_analyzer.py <pcap_file>")
        sys.exit(1)

    analyze_pcap(sys.argv[1])