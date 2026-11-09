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
    )

    # Support both visible and hidden SSIDs.
    if isinstance(ssid, str):
        ssid_information = ssid.encode("utf-8")
    else:
        ssid_information = ssid

    # Always include the SSID information element.
    packet = packet / Dot11Elt(
        ID="SSID",
        info=ssid_information
    )

    # Add wireless channel information.
    packet = packet / Dot11Elt(
        ID="DSset",
        info=bytes([channel])
    )

    return packet


packets = []

# TEST 1: Authorized AP broadcasting on an unexpected channel.
packets.append(
    create_beacon(
        "Campus_Student_WiFi",
        "02:11:22:33:44:55",
        11,
        -48
    )
)

# TEST 2: Unknown BSSID impersonating the guest network.
packets.append(
    create_beacon(
        "Campus_Guest_WiFi",
        "02:bb:cc:44:55:66",
        6,
        -52
    )
)

# TEST 3: Unknown AP with an empty hidden SSID.
packets.append(
    create_beacon(
        b"",
        "02:dd:ee:44:55:66",
        1,
        -65
    )
)

# TEST 4: Unknown AP with a 32-byte null hidden SSID.
packets.append(
    create_beacon(
        b"\x00" * 32,
        "02:ee:ff:44:55:66",
        3,
        -70
    )
)

wrpcap(
    "data/pcap/advanced_wireless.pcap",
    packets
)

print("Advanced wireless PCAP generated successfully!")
print(f"Total simulated access points: {len(packets)}")