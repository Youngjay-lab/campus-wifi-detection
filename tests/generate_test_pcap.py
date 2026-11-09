from pathlib import Path

from scapy.all import (
    RadioTap,
    Dot11,
    Dot11Beacon,
    Dot11ProbeResp,
    Dot11Elt,
    wrpcap,
)

# Get the project directory and prepare the output location.
PROJECT_DIR = Path(__file__).resolve().parent.parent
OUTPUT_FILE = PROJECT_DIR / "data" / "pcap" / "test_wireless.pcap"

OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

packets = []

# Test Access Point 1: Campus Student Wi-Fi
ap1 = (
    RadioTap(
        present="dBm_AntSignal",
        dBm_AntSignal=-45
    )
    / Dot11(
        type=0,
        subtype=8,
        addr1="ff:ff:ff:ff:ff:ff",
        addr2="02:11:22:33:44:55",
        addr3="02:11:22:33:44:55",
    )
    / Dot11Beacon()
    / Dot11Elt(ID=0, info="Campus_Student_WiFi")
    / Dot11Elt(ID=3, info=b"\x06")
)

# Test Access Point 2: Campus Guest Wi-Fi
ap2 = (
    RadioTap(
        present="dBm_AntSignal",
        dBm_AntSignal=-60
    )
    / Dot11(
        type=0,
        subtype=8,
        addr1="ff:ff:ff:ff:ff:ff",
        addr2="02:aa:bb:cc:dd:ee",
        addr3="02:aa:bb:cc:dd:ee",
    )
    / Dot11Beacon()
    / Dot11Elt(ID=0, info="Campus_Guest_WiFi")
    / Dot11Elt(ID=3, info=b"\x0b")
)

# Test Probe Response from Campus Student Wi-Fi
probe_response = (
    RadioTap(
        present="dBm_AntSignal",
        dBm_AntSignal=-50
    )
    / Dot11(
        type=0,
        subtype=5,
        addr1="02:00:00:00:00:01",
        addr2="02:11:22:33:44:55",
        addr3="02:11:22:33:44:55",
    )
    / Dot11ProbeResp()
    / Dot11Elt(ID=0, info="Campus_Student_WiFi")
    / Dot11Elt(ID=3, info=b"\x06")
)

# Add all three packets to the test capture.
packets.extend([ap1, ap2, probe_response])

# Write the packets to the PCAP file.
wrpcap(str(OUTPUT_FILE), packets)

print("Test wireless PCAP generated successfully!")
print(f"Total packets generated: {len(packets)}")
print(f"Output file: {OUTPUT_FILE}")