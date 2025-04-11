# IoT Scout

IoT Scout is a powerful tool designed for analyzing IoT devices and firmware, focusing on security assessment and information gathering. It provides capabilities for live UART analysis, firmware examination, and sensitive information detection.

![IoT Scout Banner](docs/banner.png)

## Features

- 🔍 **Live UART Analysis** (Currently under maintenance)
  - Process monitoring
  - Real-time system analysis
  - Automatic boot sequence handling

- 📦 **Firmware Analysis**
  - Automatic extraction using binwalk
  - Binary file identification
  - Common IoT component detection
  - Squashfs filesystem extraction

- 🔐 **Security Assessment**
  - Sensitive file detection
  - Password and key scanning
  - Configuration file analysis
  - Network information gathering

- 📊 **Report Generation**
  - Markdown formatted reports
  - Detailed findings categorization
  - Time-stamped documentation
  - Process listing and analysis

## Prerequisites

- Go 1.19 or higher
- Linux-based operating system
- The following tools installed:
  - binwalk
  - jefferson (for squashfs extraction)
  - file command

```bash
# Install required system packages
sudo apt-get install binwalk jefferson file

# Install required Go packages
go get github.com/c-bata/go-prompt
go get github.com/fatih/color
go get github.com/tarm/serial
go get golang.org/x/term
go get golang.org/x/text/encoding/charmap
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/darkmatter91/iot-scout.git
cd iot-scout
```

2. Build the project:
```bash
go build -o iot_scout
```

3. Make the binary executable:
```bash
chmod +x iot_scout
```

## Usage

Run the tool:
```bash
./iot_scout
```

### Menu Options

1. **Capture live data from UART** (Currently under maintenance)
   - Connects to IoT devices via UART
   - Monitors running processes
   - Analyzes system information

2. **Analyze firmware**
   - Extracts and analyzes firmware files
   - Identifies binary files and their types
   - Detects common IoT components

3. **Search for sensitive information**
   - Scans for passwords, keys, and tokens
   - Identifies configuration files
   - Detects network information

4. **Generate report**
   - Creates detailed markdown reports
   - Includes all findings and analyses
   - Time-stamped for documentation

5. **Exit**
   - Gracefully exits the program

## Report Format

Reports are generated in Markdown format with the following sections:

- Process List
- Firmware Analysis
- IoT Binaries
- Sensitive Information

Reports are saved with the filename format: `iot_scout_report_YYYYMMDD_HHMMSS.md`

## Sensitive Information Detection

The tool searches for various types of sensitive information:

- Passwords and credentials
- API keys and tokens
- Private keys and certificates
- Configuration files
- Network information
- Email addresses
- IP addresses
- MAC addresses
- URLs

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Darkma773r (https://github.com/darkmatter91)

## Acknowledgments

- Thanks to the binwalk and jefferson projects
- All contributors and testers
- The IoT security community

## Disclaimer

This tool is intended for security research and authorized testing only. Always obtain proper authorization before analyzing any device or firmware.


