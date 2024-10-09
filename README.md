# Dynamic Packet Sniffer

## Overview
Dynamic Packet Sniffer is a Python-based application that captures and analyzes network packets in real-time. This application utilizes a graphical user interface (GUI) built with Tkinter and leverages the Scapy library for network packet capture. The packets can be viewed in a user-friendly format and saved in PCAP format for further analysis using tools like Wireshark.

## Features
- **Real-time Packet Capture**: Capture network packets in real-time and view their summaries.
- **Detailed Packet Information**: View comprehensive details of individual packets directly in the application.
- **Dynamic User Interface**: The layout is adjustable and responsive, allowing for better organization and usability.
- **Save Packets in PCAP Format**: Export captured packets to a PCAP file that can be analyzed using various network tools.

## Requirements
- Python 3.x
- Tkinter (usually comes pre-installed with Python)
- Scapy

You can install Scapy using pip:
```bash
pip install scapy

Installation

    Clone the repository:

    bash

git clone <repository-url>

Navigate to the project directory:

bash

    cd <project-directory>

Usage

    Run the application:

    bash

    python packet_sniffer.py

    Click the "Start Sniffing" button to begin capturing packets.
    While packets are being captured, you can view summaries in the display area.
    To see detailed information about a specific packet, double-click on its entry in the list.
    Click the "Stop Sniffing" button to halt the packet capture.
    Click the "Save Packets" button to export the captured packets to a PCAP file (captured_packets.pcap).

License

This project is licensed under the MIT License. See the LICENSE file for more details.
Acknowledgments

    Scapy - For packet manipulation and capture.
    Tkinter - For creating the GUI.
    Wireshark - For analyzing the exported PCAP files.

Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue if you encounter any problems.
