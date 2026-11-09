import sqlite3
import re
from pathlib import Path


# --------------------------------------------------
# DATABASE CONFIGURATION
# --------------------------------------------------

PROJECT_DIR = Path(__file__).resolve().parent.parent

DATABASE_PATH = PROJECT_DIR / "data" / "campus_wifi.db"

VALID_CHANNELS = set(range(1, 15))

INCIDENT_SEVERITIES = {
    "UNKNOWN AP": "MEDIUM",
    "POTENTIAL EVIL TWIN": "HIGH",
    "SUSPICIOUS CONFIGURATION": "HIGH"
}

VALID_INCIDENT_STATUSES = {
    "Open",
    "Investigating",
    "Resolved"
}


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
    """Create the authorized AP and security incident tables."""

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

        connection.execute("""
            CREATE TABLE IF NOT EXISTS security_incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ssid TEXT,
                bssid TEXT NOT NULL,
                channel INTEGER,
                signal_strength INTEGER,
                frame_type TEXT,
                classification TEXT NOT NULL,
                severity TEXT NOT NULL
                    CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH')),
                reason TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open'
                    CHECK(status IN (
                        'Open',
                        'Investigating',
                        'Resolved'
                    )),
                detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        connection.commit()

        print("Database initialized successfully!")
        print("Authorized access point table ready.")
        print("Security incident table ready.")

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
# LOG SECURITY INCIDENT
# --------------------------------------------------

def log_incident(network):
    """Save a suspicious access point detection as an incident."""

    classification = network.get("Classification")

    if classification not in INCIDENT_SEVERITIES:
        return False

    bssid = network.get("BSSID")

    if not isinstance(bssid, str):
        raise ValueError("Incident BSSID must be a string.")

    bssid = bssid.strip().lower()

    mac_pattern = r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$"

    if not re.fullmatch(mac_pattern, bssid):
        raise ValueError("Invalid incident BSSID.")

    severity = INCIDENT_SEVERITIES[classification]

    connection = connect_db()

    try:

        connection.execute("""
            INSERT INTO security_incidents (
                ssid,
                bssid,
                channel,
                signal_strength,
                frame_type,
                classification,
                severity,
                reason
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            network.get("SSID"),
            bssid,
            network.get("Channel"),
            network.get("Signal Strength (dBm)"),
            network.get("Frame Type"),
            classification,
            severity,
            network.get("Reason", "No reason provided.")
        ))

        connection.commit()

        return True

    finally:
        connection.close()


# --------------------------------------------------
# RETRIEVE SECURITY INCIDENTS
# --------------------------------------------------

def get_incidents(status=None):
    """Retrieve security incidents, optionally filtering by status."""

    if status is not None and status not in VALID_INCIDENT_STATUSES:
        raise ValueError("Invalid incident status.")

    connection = connect_db()

    try:

        if status:

            records = connection.execute("""
                SELECT *
                FROM security_incidents
                WHERE status = ?
                ORDER BY detected_at DESC, id DESC
            """, (status,)).fetchall()

        else:

            records = connection.execute("""
                SELECT *
                FROM security_incidents
                ORDER BY detected_at DESC, id DESC
            """).fetchall()

        return [dict(record) for record in records]

    finally:
        connection.close()


# --------------------------------------------------
# UPDATE INCIDENT STATUS
# --------------------------------------------------

def update_incident_status(incident_id, new_status):
    """Update the status of an existing security incident."""

    if not isinstance(incident_id, int) or isinstance(incident_id, bool):
        raise ValueError("Incident ID must be an integer.")

    if incident_id <= 0:
        raise ValueError("Incident ID must be positive.")

    if new_status not in VALID_INCIDENT_STATUSES:
        raise ValueError("Invalid incident status.")

    connection = connect_db()

    try:

        cursor = connection.execute("""
            UPDATE security_incidents
            SET status = ?
            WHERE id = ?
        """, (new_status, incident_id))

        connection.commit()

        if cursor.rowcount > 0:
            return True

        return False

    finally:
        connection.close()


# --------------------------------------------------
# PROGRAM ENTRY POINT
# --------------------------------------------------

if __name__ == "__main__":
    create_tables()