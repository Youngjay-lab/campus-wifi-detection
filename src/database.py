import sqlite3
import re
from pathlib import Path


# --------------------------------------------------
# DATABASE CONFIGURATION
# --------------------------------------------------

PROJECT_DIR = Path(__file__).resolve().parent.parent

DATABASE_PATH = PROJECT_DIR / "data" / "campus_wifi.db"

VALID_CHANNELS = set(range(1, 15))


# --------------------------------------------------
# DATABASE CONNECTION
# --------------------------------------------------

def connect_db():
    """Connect to the SQLite database."""

    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH, timeout=10)

    connection.row_factory = sqlite3.Row

    return connection


# --------------------------------------------------
# INPUT VALIDATION
# --------------------------------------------------

def validate_access_point(ssid, bssid, location, channel):

    if not isinstance(ssid, str) or not ssid.strip():
        raise ValueError("SSID cannot be empty.")

    if len(ssid.encode("utf-8")) > 32:
        raise ValueError("SSID cannot exceed 32 bytes.")

    if not isinstance(bssid, str):
        raise ValueError("BSSID must be a string.")

    bssid = bssid.strip().lower()

    mac_pattern = r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$"

    if not re.fullmatch(mac_pattern, bssid):
        raise ValueError("Invalid BSSID format.")

    if not isinstance(location, str) or not location.strip():
        raise ValueError("Location cannot be empty.")

    if not isinstance(channel, int) or isinstance(channel, bool):
        raise ValueError("Channel must be an integer.")

    if channel not in VALID_CHANNELS:
        raise ValueError("Channel must be between 1 and 14.")

    return ssid.strip(), bssid, location.strip(), channel


# --------------------------------------------------
# DATABASE TABLE CREATION
# --------------------------------------------------

def create_tables():
    """Create the authorized access point table."""

    connection = connect_db()

    try:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS authorized_access_points (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ssid TEXT NOT NULL,
                bssid TEXT NOT NULL UNIQUE,
                location TEXT NOT NULL,
                channel INTEGER NOT NULL
                    CHECK(channel BETWEEN 1 AND 14),
                status TEXT NOT NULL DEFAULT 'authorized'
                    CHECK(status IN ('authorized', 'inactive')),
                date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        connection.commit()

        print("Database initialized successfully!")
        print("Authorized access point table created.")

    finally:
        connection.close()


# --------------------------------------------------
# REGISTER ACCESS POINT
# --------------------------------------------------

def add_access_point(ssid, bssid, location, channel):
    """Register a new authorized access point."""

    ssid, bssid, location, channel = validate_access_point(
        ssid, bssid, location, channel
    )

    connection = connect_db()

    try:

        connection.execute("""
            INSERT INTO authorized_access_points
            (ssid, bssid, location, channel)
            VALUES (?, ?, ?, ?)
        """, (ssid, bssid, location, channel))

        connection.commit()

        print(f"Access point '{ssid}' registered successfully.")

        return True

    except sqlite3.IntegrityError:

        print(f"An access point with BSSID {bssid} already exists.")

        return False

    finally:
        connection.close()


# --------------------------------------------------
# RETRIEVE AUTHORIZED ACCESS POINTS
# --------------------------------------------------

def get_authorized_access_points():
    """Retrieve all currently authorized access points."""

    connection = connect_db()

    try:

        records = connection.execute("""
            SELECT *
            FROM authorized_access_points
            WHERE status = 'authorized'
            ORDER BY id
        """).fetchall()

        return [dict(record) for record in records]

    finally:
        connection.close()


# --------------------------------------------------
# DEACTIVATE ACCESS POINT
# --------------------------------------------------

def deactivate_access_point(bssid):
    """Change an access point's status to inactive."""

    if not isinstance(bssid, str):
        raise ValueError("BSSID must be a string.")

    bssid = bssid.strip().lower()

    mac_pattern = r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$"

    if not re.fullmatch(mac_pattern, bssid):
        raise ValueError("Invalid BSSID format.")

    connection = connect_db()

    try:

        cursor = connection.execute("""
            UPDATE authorized_access_points
            SET status = 'inactive'
            WHERE bssid = ?
        """, (bssid,))

        connection.commit()

        if cursor.rowcount > 0:
            print(f"Access point {bssid} deactivated.")
            return True

        print(f"Access point {bssid} was not found.")
        return False

    finally:
        connection.close()


# --------------------------------------------------
# PROGRAM ENTRY POINT
# --------------------------------------------------

if __name__ == "__main__":
    create_tables()