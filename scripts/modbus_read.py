#!/usr/bin/env python3
"""
================================================================================
OT Security Assessment Tool — Modbus TCP Unauthenticated Read
================================================================================
Project:    Water Treatment ICS Security Assessment
Scenario:   Reproducing 2023 CyberAv3ngers attack on Municipal Water Authority
            of Aliquippa, Pennsylvania
Author:     Deepak Varma
Background: 9+ years operations and process safety — Reliance Industries
            (world's largest oil refinery) and Tata Steel

Purpose:
    Demonstrates that Modbus TCP has zero built-in authentication.
    Any device on the network can connect to port 502 and read all
    process variable values without any credentials.

    In a real water treatment plant, this means an attacker can
    silently monitor:
        - Whether pumps are running
        - Current pipeline pressure readings
        - Whether safety alarms are active
        - Whether chlorination is operating

    This is exactly what CyberAv3ngers did before taking control
    of the Aliquippa water treatment facility in November 2023.

Modbus Addressing (OpenPLC mapping):
    Coil 0  (%QX0.0) — pump_running        (BOOL: TRUE/FALSE)
    Coil 1  (%QX0.1) — high_pressure_alarm (BOOL: TRUE/FALSE)
    Coil 2  (%QX0.2) — chlorine_dosing     (BOOL: TRUE/FALSE)
    Reg  0  (%QW0)   — system_pressure     (INT:  PSI value)

IEC 62443 Gap Demonstrated:
    SR 1.1 — No identification or authentication on Modbus TCP
    SR 4.1 — Process data transmitted in cleartext, no encryption

Usage:
    python modbus_read.py

Requirements:
    pip install pymodbus
================================================================================
"""

from pymodbus.client import ModbusTcpClient
import sys
import datetime

# ─────────────────────────────────────────────────────────────────────────────
# TARGET CONFIGURATION
# In a real assessment, this would be the IP of the target PLC.
# In this lab, OpenPLC runs on localhost (Docker port-mapped to 127.0.0.1:502)
# ─────────────────────────────────────────────────────────────────────────────
TARGET_IP   = '127.0.0.1'   # OpenPLC container — Modbus TCP listener
TARGET_PORT = 502            # Standard Modbus TCP port (IANA assigned)
UNIT_ID     = 1              # Modbus slave/unit ID (OpenPLC default = 1)


def print_banner():
    """Print assessment header with context information."""
    print("=" * 70)
    print("  OT SECURITY ASSESSMENT — Unauthenticated Modbus TCP Read")
    print("  Scenario: 2023 CyberAv3ngers Water Treatment Attack Simulation")
    print("=" * 70)
    print(f"  Timestamp : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Target    : {TARGET_IP}:{TARGET_PORT}")
    print(f"  Protocol  : Modbus TCP (RFC standard — no auth layer)")
    print(f"  Unit ID   : {UNIT_ID}")
    print("=" * 70)
    print()


def connect_to_plc(ip, port):
    """
    Establish unauthenticated connection to PLC.

    Modbus TCP uses a standard TCP handshake — no username,
    no password, no certificate, no token. If port 502 is
    reachable, the connection succeeds immediately.

    Args:
        ip   (str): Target PLC IP address
        port (int): Target Modbus TCP port (default 502)

    Returns:
        ModbusTcpClient: Connected client object
    """
    print("[*] Attempting connection to PLC...")
    print("[*] Credentials required: NONE")
    print("[*] Authentication mechanism: NONE")
    print()

    client = ModbusTcpClient(ip, port=port)
    connected = client.connect()

    if connected:
        print("[+] CONNECTION ESTABLISHED — zero authentication required")
        print("[+] PLC is now accepting commands from this unauthorised host")
    else:
        print("[-] Connection failed — PLC may be offline or port blocked")
        sys.exit(1)

    print()
    return client


def read_coils(client, start_address, count):
    """
    Read Boolean coil values from PLC memory.

    In Modbus, 'coils' are single-bit read/write registers.
    In industrial systems they typically represent ON/OFF states:
    pump running, valve open, alarm active, relay energised, etc.

    Function Code used: FC01 (Read Coils)
    This is the same function code visible in Wireshark capture.

    Args:
        client        (ModbusTcpClient): Connected Modbus client
        start_address (int): First coil address to read
        count         (int): Number of coils to read

    Returns:
        list: Boolean values for each coil address
    """
    response = client.read_coils(start_address, count=count, slave=UNIT_ID)

    if response.isError():
        print(f"[-] Error reading coils: {response}")
        return None

    return response.bits[:count]


def read_holding_registers(client, start_address, count):
    """
    Read integer holding register values from PLC memory.

    'Holding registers' are 16-bit read/write registers used
    for numeric process values: temperature, pressure, flow rate,
    speed setpoints, etc.

    Function Code used: FC03 (Read Holding Registers)
    This is the same function code visible in Wireshark capture.

    Args:
        client        (ModbusTcpClient): Connected Modbus client
        start_address (int): First register address to read
        count         (int): Number of registers to read

    Returns:
        list: Integer values for each register address
    """
    response = client.read_holding_registers(
        start_address, count=count, slave=UNIT_ID
    )

    if response.isError():
        print(f"[-] Error reading registers: {response}")
        return None

    return response.registers


def display_process_values(coil_values, register_values):
    """
    Display all PLC process values in a readable format.

    These are the exact values an attacker would see when
    performing reconnaissance on an exposed water treatment PLC.

    Args:
        coil_values     (list): Boolean values from coil read
        register_values (list): Integer values from register read
    """
    print("─" * 70)
    print("  WATER BOOSTER STATION — Live Process Values")
    print("  (Read without authentication from Modbus TCP port 502)")
    print("─" * 70)
    print()

    # ── Coil values (Boolean ON/OFF process states) ──────────────────────
    print("  DIGITAL OUTPUTS (Coils — Function Code 01):")
    print()

    pump_status = "RUNNING ▶" if coil_values[0] else "STOPPED ■"
    alarm_status = "ACTIVE ⚠" if coil_values[1] else "CLEAR ✓"
    chlorine_status = "DOSING ▶" if coil_values[2] else "STOPPED ■"

    print(f"    pump_running        (Coil 0 / %QX0.0) : "
          f"{coil_values[0]}  [{pump_status}]")
    print(f"    high_pressure_alarm (Coil 1 / %QX0.1) : "
          f"{coil_values[1]}  [{alarm_status}]")
    print(f"    chlorine_dosing     (Coil 2 / %QX0.2) : "
          f"{coil_values[2]}  [{chlorine_status}]")
    print()

    # ── Register values (Integer process measurements) ───────────────────
    print("  ANALOG OUTPUTS (Holding Registers — Function Code 03):")
    print()

    pressure = register_values[0]
    pressure_status = "HIGH ⚠" if pressure > 75 else "NORMAL ✓"

    print(f"    system_pressure     (Reg  0 / %QW0)   : "
          f"{pressure} PSI  [{pressure_status}]")
    print()

    # ── Attack surface assessment ─────────────────────────────────────────
    print("─" * 70)
    print("  ATTACK SURFACE ASSESSMENT:")
    print()
    if coil_values[0]:
        print("  [!] pump_running = TRUE  → Write FALSE to stop water supply")
    if coil_values[2]:
        print("  [!] chlorine_dosing = TRUE  → Write FALSE to disable treatment")
    if pressure > 0:
        print(f"  [!] system_pressure = {pressure} PSI "
              f"→ Manipulate to cause pipe damage")
    print()


def main():
    """Main assessment function."""

    print_banner()

    # ── Step 1: Connect to PLC (no authentication required) ──────────────
    client = connect_to_plc(TARGET_IP, TARGET_PORT)

    # ── Step 2: Read all coil values (pump, alarm, chlorine) ─────────────
    print("[*] Reading coil values (FC01 — Read Coils)...")
    coil_values = read_coils(client, start_address=0, count=3)

    # ── Step 3: Read all register values (pressure) ───────────────────────
    print("[*] Reading holding registers (FC03 — Read Holding Registers)...")
    register_values = read_holding_registers(client, start_address=0, count=1)
    print()

    # ── Step 4: Display all process values ───────────────────────────────
    if coil_values and register_values:
        display_process_values(coil_values, register_values)

    # ── Step 5: Close connection ──────────────────────────────────────────
    client.close()

    print("=" * 70)
    print("  READ COMPLETE — Zero authentication was required")
    print("  Any device on this network can access all PLC process values")
    print("  IEC 62443 SR 1.1 and SR 4.1 — NOT MET")
    print("=" * 70)


if __name__ == "__main__":
    main()