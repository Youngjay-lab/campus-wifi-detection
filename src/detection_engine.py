from pathlib import Path
import sys

from scapy.all import rdpcap, Dot11

from database import get_authorized_access_points
from packet_analyzer import extract_network_information


def classify_network(network, authorized_access_points):
    """
    Compare an observed wireless network against
    the authorized access point database.
    """

    observed_ssid = network["SSID"]
    observed_bssid = network["BSSID"]

    # Find an authorized record with the same BSSID.
    matching_bssid = next(
        (
            ap for ap in authorized_access_points
            if ap["bssid"].lower() == observed_bssid.lower()
        ),
        None
    )

    # Find authorized networks using the same SSID.
    matching_ssid = [
        ap for ap in authorized_access_points
        if ap["ssid"] == observed_ssid
    ]

    # Case 1: BSSID is registered.
    if matching_bssid:

        if matching_bssid["ssid"] == observed_ssid:
            classification = "AUTHORIZED AP"
            reason = "BSSID and SSID match the authorized registry."

        else:
            classification = "SUSPICIOUS CONFIGURATION"
            reason = (
                "Registered BSSID is broadcasting an unexpected SSID."
            )

    # Case 2: BSSID is unknown but SSID belongs to an authorized network.
    elif matching_ssid:

        classification = "POTENTIAL EVIL TWIN"
        reason = (
            "An unregistered BSSID is broadcasting an "
            "authorized network's SSID."
        )

    # Case 3: Neither BSSID nor SSID matches.
    else:

        classification = "UNKNOWN AP"
        reason = "BSSID and SSID are not found in the authorized registry."

    return {
        "SSID": observed_ssid,
        "BSSID": observed_bssid,
        "Channel": network["Channel"],
        "Signal Strength (dBm)": network["Signal Strength (dBm)"],
        "Frame Type": network["Frame Type"],
        "Classification": classification,
        "Reason": reason
    }


def analyze_and_classify_pcap(file_path):
    """Analyze a PCAP file and classify discovered networks."""

    print("\nStarting Rogue Access Point Detection...\n")

    file_path = Path(file_path)

    if not file_path.is_file():
        print(f"Error: PCAP file not found: {file_path}")
        return

    # Load authorized access points from SQLite.
    authorized_access_points = get_authorized_access_points()

    print(
        f"Authorized access points loaded: "
        f"{len(authorized_access_points)}"
    )

    # Read captured wireless packets.
    packets = rdpcap(str(file_path))

    print(f"Total packets captured: {len(packets)}")

    detected_networks = []

    for packet in packets:

        if not packet.haslayer(Dot11):
            continue

        network = extract_network_information(packet)

        if network:
            result = classify_network(
                network,
                authorized_access_points
            )

            detected_networks.append(result)

    print("\nACCESS POINT DETECTION RESULTS")
    print("=" * 60)

    if not detected_networks:
        print("No supported wireless management frames found.")
        return

    for number, network in enumerate(detected_networks, start=1):

        print(f"\nNetwork Record {number}")
        print("-" * 40)

        for key, value in network.items():
            print(f"{key}: {value}")

    print("\nDETECTION SUMMARY")
    print("=" * 60)

    for classification in [
        "AUTHORIZED AP",
        "UNKNOWN AP",
        "POTENTIAL EVIL TWIN",
        "SUSPICIOUS CONFIGURATION"
    ]:

        count = sum(
            1 for network in detected_networks
            if network["Classification"] == classification
        )

        print(f"{classification}: {count}")

    print("\nDetection analysis completed.")


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print(
            "Usage: python src/detection_engine.py "
            "<pcap_file>"
        )
        sys.exit(1)

    analyze_and_classify_pcap(sys.argv[1])