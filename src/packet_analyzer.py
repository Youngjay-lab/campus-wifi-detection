from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11ProbeResp
from scapy.layers.dot11 import Dot11Elt, RadioTap
import sys


def extract_network_information(packet):
    """
    Extract wireless network information from Beacon
    and Probe Response management frames.
    """

    ssid = None
    ssid_visibility = "Unknown"
    channel = None
    signal_strength = None

    bssid = packet.addr3

    # Identify supported wireless management frames.
    if packet.haslayer(Dot11Beacon):
        frame_type = "Beacon"

    elif packet.haslayer(Dot11ProbeResp):
        frame_type = "Probe Response"

    else:
        return None

    # Extract wireless information elements.
    element = packet.getlayer(Dot11Elt)

    while isinstance(element, Dot11Elt):

        # SSID information element (Element ID 0).
        if element.ID == 0:

            raw_ssid = bytes(element.info)

            # Detect zero-length and null-byte hidden SSIDs.
            if not raw_ssid or not raw_ssid.strip(b"\x00"):

                ssid = None
                ssid_visibility = "Hidden"

            else:

                ssid = raw_ssid.decode(
                    "utf-8",
                    errors="replace"
                )

                ssid_visibility = "Visible"

        # DS Parameter Set (Element ID 3).
        elif element.ID == 3 and len(element.info) > 0:

            channel = element.info[0]

        element = element.payload

    # Extract received signal strength when available.
    if packet.haslayer(RadioTap):

        radiotap = packet.getlayer(RadioTap)

        if hasattr(radiotap, "dBm_AntSignal"):

            signal_strength = radiotap.dBm_AntSignal

    return {
        "SSID": ssid,
        "SSID Visibility": ssid_visibility,
        "BSSID": bssid,
        "Channel": channel,
        "Signal Strength (dBm)": signal_strength,
        "Frame Type": frame_type
    }


def analyze_pcap(file_path):
    """
    Read a PCAP file and display extracted wireless
    management frame information.
    """

    print("\nStarting wireless packet analysis...\n")

    try:
        packets = rdpcap(file_path)

    except (OSError, ValueError) as error:

        print(f"Error reading PCAP file: {error}")
        return

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

    print(
        f"Management frames analyzed: "
        f"{len(detected_networks)}"
    )


if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage: python src/packet_analyzer.py "
            "<pcap_file>"
        )

        sys.exit(1)

    analyze_pcap(sys.argv[1])