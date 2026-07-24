#!/usr/bin/env python3
"""
================================================================================
OT Security Control — Modbus TCP Function Code Filter (Deep Packet Inspection)
================================================================================
Project:    Water Treatment ICS Security Assessment
Scenario:   Reproducing 2023 CyberAv3ngers attack on Municipal Water Authority
            of Aliquippa, Pennsylvania
Author:     Deepak Varma
Background: 9+ years operations and process safety — Reliance Industries
            (world's largest oil refinery) and Tata Steel

Purpose:
    Implements Control 2 of 3 — a protocol-aware Modbus security proxy
    that performs Deep Packet Inspection (DPI) on every Modbus message.

    This proxy sits between clients and the PLC on port 5020, inspects
    the Modbus function code in each message, and applies the following
    policy:

        READ operations  (FC 01, 02, 03, 04) — ALLOWED from any source
        WRITE operations (FC 05, 06, 15, 16) — BLOCKED from unauthorised
                                                sources, ALLOWED from HMI

    This mirrors the capability of enterprise OT security products:
        - Claroty CTD (Continuous Threat Detection)
        - Tofino Security Appliance
        - Dragos Platform
        - Nozomi Networks Guardian

    The proxy also logs every blocked attempt with source IP, timestamp,
    and function code — feeding into the audit trail (Control 3).

IEC 62443 Control Implemented:
    SR 3.5 — Input Validation
    "The ICS shall validate inputs from all sources to ensure that the
    inputs are within the specified range and format."

Modbus Function Code Reference:
    FC 01 — Read Coils               (READ  — ALLOWED)
    FC 02 — Read Discrete Inputs     (READ  — ALLOWED)
    FC 03 — Read Holding Registers   (READ  — ALLOWED)
    FC 04 — Read Input Registers     (READ  — ALLOWED)
    FC 05 — Write Single Coil        (WRITE — BLOCKED from unauth)
    FC 06 — Write Single Register    (WRITE — BLOCKED from unauth)
    FC 15 — Write Multiple Coils     (WRITE — BLOCKED from unauth)
    FC 16 — Write Multiple Registers (WRITE — BLOCKED from unauth)

Modbus TCP Packet Structure (MBAP Header):
    Byte 0-1 : Transaction Identifier
    Byte 2-3 : Protocol Identifier (always 0x0000 for Modbus)
    Byte 4-5 : Length of remaining bytes
    Byte 6   : Unit Identifier (slave ID)
    Byte 7   : Function Code  ← THIS is what we inspect
    Byte 8+  : Data

Usage:
    python modbus_proxy.py
    (Run in a separate terminal — must stay running)

Requirements:
    No external libraries — uses Python standard library only
================================================================================
"""

import socket
import threading
import datetime
import sys

# ─────────────────────────────────────────────────────────────────────────────
# PROXY CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

# The IP of the authorised SCADA/HMI system (Scada-LTS Docker container)
# Only this source is permitted to send write commands to the PLC
AUTHORISED_HMI_IP = '172.18.0.4'

# The PLC we are protecting (OpenPLC on localhost port 502)
PLC_HOST = '127.0.0.1'
PLC_PORT = 502

# The port this proxy listens on (clients connect here instead of port 502)
PROXY_PORT = 5020

# Modbus function codes that modify PLC state (write operations)
# These are blocked from any source except the authorised HMI
WRITE_FUNCTION_CODES = {
    5:  "Write Single Coil",
    6:  "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    22: "Mask Write Register",
    23: "Read/Write Multiple Registers"
}

# Modbus function codes that only read PLC state (read operations)
# These are allowed from any source
READ_FUNCTION_CODES = {
    1:  "Read Coils",
    2:  "Read Discrete Inputs",
    3:  "Read Holding Registers",
    4:  "Read Input Registers"
}


def log(level, message):
    """
    Write a timestamped log entry to console.

    Args:
        level   (str): Log level — INFO, ALLOW, BLOCK, WARN, ERROR
        message (str): Log message
    """
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    level_display = {
        'INFO':  '[INFO ]',
        'ALLOW': '[ALLOW]',
        'BLOCK': '[BLOCK]',
        'WARN':  '[WARN ]',
        'ERROR': '[ERROR]'
    }.get(level, '[INFO ]')

    print(f"{timestamp} {level_display} {message}")
    sys.stdout.flush()  # Ensure immediate output


def build_modbus_exception(request_data, exception_code=0x01):
    """
    Build a Modbus exception response to send back to blocked clients.

    When a write command is blocked, the proxy sends a proper Modbus
    exception response rather than dropping the connection silently.
    This is more protocol-correct and informative.

    Exception Code 0x01 = Illegal Function
    Exception Code 0x02 = Illegal Data Address
    Exception Code 0x03 = Illegal Data Value

    The exception response format:
        Bytes 0-5 : Echo the MBAP header from the request
        Byte  6   : Function code with high bit set (FC | 0x80)
        Byte  7   : Exception code

    Args:
        request_data   (bytes): Original Modbus request
        exception_code (int):   Modbus exception code to return

    Returns:
        bytes: Properly formatted Modbus exception response
    """
    if len(request_data) < 8:
        return None

    # Echo MBAP header (bytes 0-5), set error bit on function code
    mbap_header      = request_data[:6]
    error_func_code  = bytes([request_data[7] | 0x80])
    exception        = bytes([exception_code])

    return mbap_header + error_func_code + exception


def inspect_and_filter(data, source_ip):
    """
    Inspect a Modbus TCP packet and apply the function code filter policy.

    Extracts the function code from byte 7 of the Modbus TCP frame
    (after the 6-byte MBAP header and 1-byte unit identifier).

    Policy:
        - READ function codes (1-4)  → ALLOW from any source
        - WRITE function codes (5+)  → ALLOW only from authorised HMI
        - WRITE function codes (5+)  → BLOCK from all other sources

    Args:
        data      (bytes): Raw Modbus TCP packet
        source_ip (str):   Source IP address of the client

    Returns:
        tuple: (allow: bool, function_code: int, fc_name: str)
    """
    # Minimum valid Modbus TCP frame is 8 bytes
    if len(data) < 8:
        return True, None, "Unknown (packet too short)"

    function_code = data[7]

    # ── Check if this is a write function code ────────────────────────────
    if function_code in WRITE_FUNCTION_CODES:
        fc_name = WRITE_FUNCTION_CODES[function_code]

        if source_ip == AUTHORISED_HMI_IP:
            # Authorised HMI is allowed to write
            return True, function_code, fc_name
        else:
            # Unauthorised source attempting a write — BLOCK
            return False, function_code, fc_name

    # ── Check if this is a read function code ─────────────────────────────
    elif function_code in READ_FUNCTION_CODES:
        fc_name = READ_FUNCTION_CODES[function_code]
        return True, function_code, fc_name

    # ── Unknown function code — allow but warn ────────────────────────────
    else:
        return True, function_code, f"Unknown FC{function_code}"


def handle_client(client_socket, client_address):
    """
    Handle a single client connection through the proxy.

    For each connection:
        1. Accept the client connection
        2. Open a corresponding connection to the real PLC
        3. For each message received from the client:
           a. Inspect the Modbus function code
           b. If BLOCKED: send exception response, log the attempt
           c. If ALLOWED: forward to PLC, return response to client
        4. Close both connections when done

    Args:
        client_socket  (socket): Connected client socket
        client_address (tuple):  Client (ip, port) tuple
    """
    source_ip   = client_address[0]
    source_port = client_address[1]

    log('INFO', f"New connection from {source_ip}:{source_port}")

    # Open connection to the real PLC
    plc_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        plc_socket.connect((PLC_HOST, PLC_PORT))
        log('INFO', f"Proxy connection established to PLC at "
                    f"{PLC_HOST}:{PLC_PORT}")

        # ── Process each Modbus message in this connection ────────────────
        while True:
            # Receive data from client
            data = client_socket.recv(1024)

            # Empty data means client disconnected
            if not data:
                log('INFO', f"Client {source_ip} disconnected")
                break

            # ── Inspect the function code and apply filter policy ─────────
            allowed, fc, fc_name = inspect_and_filter(data, source_ip)

            if not allowed:
                # ── BLOCKED: Unauthorised write attempt ───────────────────
                log('BLOCK',
                    f"FC{fc:02d} ({fc_name}) from UNAUTHORISED {source_ip} "
                    f"→ BLOCKED | IEC 62443 SR 3.5")

                # Send proper Modbus exception response to client
                exception_response = build_modbus_exception(data)
                if exception_response:
                    client_socket.send(exception_response)

            else:
                # ── ALLOWED: Forward to PLC and return response ───────────
                fc_type = "WRITE" if fc in WRITE_FUNCTION_CODES else "READ"

                if fc_type == "WRITE":
                    log('ALLOW',
                        f"FC{fc:02d} ({fc_name}) WRITE from AUTHORISED "
                        f"HMI {source_ip} → forwarded to PLC")
                else:
                    log('ALLOW',
                        f"FC{fc:02d} ({fc_name}) READ from "
                        f"{source_ip} → forwarded to PLC")

                # Forward request to real PLC
                plc_socket.send(data)

                # Return PLC response to client
                response = plc_socket.recv(1024)
                if response:
                    client_socket.send(response)

    except ConnectionRefusedError:
        log('ERROR', f"Cannot connect to PLC at {PLC_HOST}:{PLC_PORT} "
                     f"— is OpenPLC running?")
    except Exception as e:
        log('WARN', f"Connection from {source_ip} ended: {e}")
    finally:
        client_socket.close()
        plc_socket.close()


def start_proxy():
    """
    Start the Modbus security proxy server.

    Binds to PROXY_PORT and accepts client connections.
    Each connection is handled in a separate thread to allow
    multiple simultaneous clients (e.g. SCADA + attacker).
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Allow immediate reuse of port after restart
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind(('', PROXY_PORT))
    server_socket.listen(10)

    # ── Print startup banner ──────────────────────────────────────────────
    print("=" * 70)
    print("  OT SECURITY CONTROL — Modbus TCP Function Code Filter")
    print("  IEC 62443 SR 3.5 — Deep Packet Inspection Proxy")
    print("=" * 70)
    log('INFO', f"Proxy listening on port {PROXY_PORT}")
    log('INFO', f"Forwarding allowed traffic to PLC at {PLC_HOST}:{PLC_PORT}")
    log('INFO', f"Authorised HMI (write-permitted): {AUTHORISED_HMI_IP}")
    log('INFO', f"Write FCs blocked from unauth sources: "
                f"{sorted(WRITE_FUNCTION_CODES.keys())}")
    log('INFO', f"Read FCs allowed from all sources: "
                f"{sorted(READ_FUNCTION_CODES.keys())}")
    print("=" * 70)
    print()

    # ── Accept and handle client connections ──────────────────────────────
    while True:
        try:
            client_socket, client_address = server_socket.accept()

            # Handle each client in a separate daemon thread
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address)
            )
            client_thread.daemon = True
            client_thread.start()

        except KeyboardInterrupt:
            log('INFO', "Proxy shutdown requested — stopping")
            server_socket.close()
            sys.exit(0)


if __name__ == "__main__":
    start_proxy()