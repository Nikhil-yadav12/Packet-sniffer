
# GUI Packet Sniffer

This project is a GUI-based packet sniffer application built using Python's Tkinter and Scapy libraries. It provides an interface to capture, display, and save network packets. 

## Features
- **Start Sniffing**: Start capturing network packets in real-time.
- **Stop Sniffing**: Stop the packet capture process.
- **Save Packets**: Save the captured packets to a PCAP file.
- **Packet Display**: View a summary of each captured packet.
- **Packet Details**: View detailed information about a selected packet.

# Requirements for GUI Packet Sniffer Application

## 1. Software Requirements
- **Python**: Version 3.6 or higher
- **Libraries**:
  - `tkinter`: For creating the GUI components.
  - `scapy`: For packet sniffing and handling.
  - `threading`: To run the packet sniffing process in a separate thread.

## 2. Python Package Installation
- Ensure that the following Python packages are installed:
  ```bash
  pip install scapy


## How to Run
1. Ensure you have Python installed on your system.
2. Install Scapy using the command:
   ```bash
   pip install scapy
   ```
3. Run the application using the command:
   ```bash
   python gui_packet_sniffer.py
   ```

## Code Overview
The application is structured into the following sections:
1. **GUI Setup**: Creates the main window, navbar, packet display, and details sections using Tkinter.
2. **Packet Sniffing**: Uses Scapy's `sniff()` function to capture network packets.
3. **Packet Display**: Displays the captured packets and their details in the GUI.
4. **Packet Save**: Saves captured packets into a `.pcap` file format.

## File Details
- **File Name**: `gui_packet_sniffer.py`
- **Primary Libraries Used**:
  - `tkinter` for the GUI.
  - `scapy` for packet capture and handling.
  - `threading` to handle packet sniffing in the background.

## Usage
- **Double-click on a packet** in the list to view its details.
- Use the **Save Packets** button to export the captured data to a PCAP file for analysis.

## License
This project is open-source and available for modification and distribution.
