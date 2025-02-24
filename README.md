# BlueSpy 2

BlueSpy 2 is an advanced, cross-platform Python Bluetooth security testing tool for Classic and BLE devices—featuring scanning, vulnerability (CVE) checks, pairing attacks, fuzzing, MITM proxy, and a scripting engine for authorized assessments. Built in homage to the original BlueSpy by TarlogicSecurity, BlueSpy++ consolidates cutting-edge Bluetooth security techniques into one powerful tool.

---

## Features

- **Cross-Platform Scanning**  
  - **Classic Bluetooth:** Device discovery via PyBluez (Linux, Windows, macOS).  
  - **BLE:** Asynchronous scanning using Bleak.

- **Unified Device Representation**  
  Stores device details (MAC, name, type, class, RSSI) for both Classic and BLE devices.

- **Service Enumeration**  
  - **Classic:** SDP service queries (e.g., RFCOMM channels).  
  - **BLE:** GATT service and characteristic discovery via Bleak.

- **CVE & Vulnerability Checks**  
  - Heuristic-based detection of default PIN usage and insecure chipsets.  
  - Optional CVE lookup via the NVD API for known Bluetooth vulnerabilities.

- **Pairing Attack Simulation**  
  - **Classic:** Attempts pairing using common default PINs (e.g., `0000`, `1234`).  
  - **BLE:** Detects insecure “Just Works” pairing that lacks authentication.

- **Fuzzing Capabilities**  
  - **Classic Fuzzing:** Sends random data to RFCOMM services to uncover buffer overflows.  
  - **BLE Fuzzing:** Writes randomized payloads to writable GATT characteristics.

- **MITM Proxy (Proof-of-Concept)**  
  Demonstrates intercepting Classic Bluetooth RFCOMM communications by relaying data between client and target.

- **Scripting Engine**  
  Automate workflows using a simple command script (e.g., `SCAN`, `TARGET <MAC>`, `CVE`, `PAIR`, `FUZZ`, `MITM`, `REPORT`).

- **Enhanced Logging & Reporting**  
  - Detailed console logs with actionable findings.  
  - Generate reports in JSON and HTML formats for further analysis or integration with other tools.

- **Asynchronous & Concurrent Operations**  
  Utilizes Python’s asyncio for efficient, non-blocking BLE and network I/O.

---

## Installation

### Requirements

- **Python 3.7+**
- **PyBluez** (for Classic Bluetooth)
- **Bleak** (for BLE)
- **Requests** (optional, for CVE lookup)

Install dependencies with:

```bash
pip install pybluez bleak requests
```

> **Note:**  
> On Linux, you may need to run the tool with root privileges (e.g., using `sudo`) and ensure that BlueZ is installed and the Bluetooth service is running.

---

## Usage

Run the tool directly via command-line:

```bash
python bluespy_adv.py --scan --scan-time 10
```

### Command-Line Options

- `--scan, -s`  
  Scan for nearby Bluetooth devices.

- `--scan-time TIME`  
  Set the scanning duration in seconds (default: 8).

- `--target ADDR, -t ADDR`  
  Specify the target device’s Bluetooth address (MAC).

- `--cve`  
  Check discovered devices against known vulnerabilities/CVEs.

- `--pair`  
  Attempt pairing attacks (e.g., default PIN testing).

- `--fuzz`  
  Fuzz target device services (RFCOMM for Classic, GATT for BLE).

- `--mitm`  
  Launch a MITM proxy (Classic RFCOMM only).

- `--script FILE`  
  Execute commands from a script file. The script supports:
  - `SCAN [duration]`
  - `TARGET <MAC>`
  - `CVE`
  - `PAIR`
  - `FUZZ`
  - `MITM`
  - `REPORT JSON <filename>` or `REPORT HTML <filename>`

- `--json FILE`  
  Save the scan report in JSON format.

- `--html FILE`  
  Save the scan report in HTML format.

- `--no-prompt`  
  Bypass the initial confirmation prompt (for authorized use only).

### Example

To scan for devices, check for vulnerabilities, perform a pairing attack, fuzz the target, and save a JSON report:

```bash
python bluespy_adv.py --scan --target AA:BB:CC:DD:EE:FF --cve --pair --fuzz --json report.json
```

---

## Disclaimer

**WARNING:** BlueSpy++ is intended strictly for ethical security testing and research on devices you own or have explicit permission to test. Unauthorized scanning, pairing, fuzzing, or MITM activities are illegal and unethical. Use this tool responsibly. The authors assume no liability for misuse.

---

## Credits

BlueSpy++ is developed as an enhanced successor to the original BlueSpy project by [TarlogicSecurity](https://github.com/TarlogicSecurity). We pay homage to the original creators and the vibrant community advancing Bluetooth security research.

---

## Contributing

Contributions, bug reports, and feature requests are welcome. Please open an issue or submit a pull request with detailed explanations. Ensure all contributions comply with ethical guidelines and legal standards.

---

## License

This project is released under the MIT License. See the [LICENSE](LICENSE) file for details.

---



