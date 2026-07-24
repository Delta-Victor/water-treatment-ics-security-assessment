from pymodbus.client import ModbusTcpClient
import time

print("=== Proxy Retest: Write via port 5020 ===")
print("Testing if proxy blocks write commands from unauthorised source")
print("")

client = ModbusTcpClient('127.0.0.1', port=5020)
client.connect()

print("Attempting to write FALSE to pump_running via proxy...")
result = client.write_coil(0, False)
print(f"Result: {result}")
print("")

client.close()
print("=== Proxy retest complete ===")