from src.database import (
    create_tables,
    add_access_point,
    get_authorized_access_points
)


def test_database_validation():

    print("\nSTARTING DATABASE VALIDATION TESTS")
    print("=" * 45)

    create_tables()

    # Test 1: Duplicate BSSID
    print("\nTEST 1: Duplicate BSSID")

    result = add_access_point(
        ssid="Duplicate_Test_WiFi",
        bssid="02:11:22:33:44:55",
        location="Test Laboratory",
        channel=6
    )

    if result is False:
        print("PASS: Duplicate BSSID rejected.")
    else:
        print("FAIL: Duplicate BSSID was accepted.")

    # Test 2: Invalid BSSID
    print("\nTEST 2: Invalid BSSID")

    try:
        add_access_point(
            ssid="Invalid_Test_WiFi",
            bssid="invalid-mac-address",
            location="Test Laboratory",
            channel=6
        )

        print("FAIL: Invalid BSSID was accepted.")

    except ValueError as error:
        print(f"PASS: Invalid BSSID rejected. ({error})")

    # Test 3: Invalid channel
    print("\nTEST 3: Invalid Channel")

    try:
        add_access_point(
            ssid="Invalid_Channel_WiFi",
            bssid="02:11:22:33:44:99",
            location="Test Laboratory",
            channel=20
        )

        print("FAIL: Invalid channel was accepted.")

    except ValueError as error:
        print(f"PASS: Invalid channel rejected. ({error})")

    # Display current authorized access points
    print("\nCURRENT AUTHORIZED ACCESS POINTS")
    print("-" * 45)

    access_points = get_authorized_access_points()

    for ap in access_points:
        print(f"SSID: {ap['ssid']}")
        print(f"BSSID: {ap['bssid']}")
        print(f"Status: {ap['status']}")
        print()

    print("DATABASE VALIDATION TESTS COMPLETED.")


if __name__ == "__main__":
    test_database_validation()