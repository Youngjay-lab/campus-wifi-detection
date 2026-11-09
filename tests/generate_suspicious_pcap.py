from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, wrpcap


def create_beacon(ssid, bssid, channel, signal=-50):

    packet = (
        RadioTap(
            present=0x20,
            dBm_AntSignal=signal
        )
        / Dot11(
            type=0,
            subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=bssid,
            addr3=bssid
        )
        / Dot11Beacon()
        / Dot11Elt(ID="SSID", info=ssid.encode())
        / Dot11Elt(ID="DSset", info=bytes([channel]))
    )

    return packet


packets = []

# TEST 1: Unknown Access Point
packets.append(
    create_beacon(
        "CoffeeShop_Free_WiFi",
        "02:cc:bb:11:22:33",
        6,
        -55
    )
)

# TEST 2: Potential Evil Twin
packets.append(
    create_beacon(
        "Campus_Student_WiFi",
        "02:bb:cc:11:22:33",
        6,
        -48
    )
)

# TEST 3: Suspicious Configuration
packets.append(
    create_beacon(
        "Campus_Staff_WiFi",
        "02:11:22:33:44:55",
        11,
        -60
    )
)

wrpcap("data/pcap/suspicious_wireless.pcap", packets)

print("Suspicious wireless PCAP generated successfully!")
print(f"Total simulated access points: {len(packets)}")