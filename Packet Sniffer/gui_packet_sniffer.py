import tkinter as tk
from tkinter import scrolledtext, messagebox, Listbox, SINGLE, END, filedialog
from scapy.all import sniff, wrpcap
import threading

class PacketSnifferApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Dynamic Packet Sniffer")
        self.master.geometry("800x600")

        # Create a frame for the navbar
        self.navbar_frame = tk.Frame(self.master)
        self.navbar_frame.grid(row=0, column=0, sticky="ew")

        # Create buttons for the navbar
        self.start_button = tk.Button(self.navbar_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.stop_button = tk.Button(self.navbar_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.save_button = tk.Button(self.navbar_frame, text="Save Packets", command=self.save_packets, state=tk.DISABLED)
        self.save_button.pack(side=tk.LEFT, padx=5, pady=5)

        # Create a frame for the packet display
        self.packet_frame = tk.Frame(self.master, relief=tk.RAISED, borderwidth=1)
        self.packet_frame.grid(row=1, column=0, sticky="nsew")

        # Create a text area for displaying packets
        self.packet_display = scrolledtext.ScrolledText(self.packet_frame, wrap=tk.WORD, font=("Arial", 10))
        self.packet_display.pack(pady=10, fill=tk.BOTH, expand=True)

        # Create a Listbox to show captured packets
        self.packet_listbox = Listbox(self.packet_frame, selectmode=SINGLE, font=("Arial", 10))
        self.packet_listbox.pack(pady=10, fill=tk.BOTH, expand=True)

        # Create a frame for the packet details
        self.details_frame = tk.Frame(self.master, relief=tk.RAISED, borderwidth=1)
        self.details_frame.grid(row=1, column=1, sticky="nsew")

        # Create a text area to show packet details
        self.details_display = scrolledtext.ScrolledText(self.details_frame, wrap=tk.WORD, font=("Arial", 10))
        self.details_display.pack(pady=10, fill=tk.BOTH, expand=True)

        # Configure grid weights to make sections expandable
        self.master.grid_columnconfigure(0, weight=1)
        self.master.grid_columnconfigure(1, weight=1)
        self.master.grid_rowconfigure(1, weight=1)

        self.sniffer_running = False
        self.sniffer_thread = None
        self.packets = []  # List to store captured packets

        # Bind double-click event on Listbox to show packet details
        self.packet_listbox.bind("<Double-Button-1>", self.show_packet_details)

    def start_sniffing(self):
        self.sniffer_running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.DISABLED)  # Disable save button until packets are captured
        self.packet_display.delete(1.0, tk.END)  # Clear previous packets
        self.packet_listbox.delete(0, END)  # Clear previous packets in Listbox
        self.details_display.delete(1.0, tk.END)  # Clear previous packet details

        # Start sniffing in a new thread
        self.sniffer_thread = threading.Thread(target=self.sniff_packets)
        self.sniffer_thread.daemon = True  # Allow thread to close when the main program exits
        self.sniffer_thread.start()

    def stop_sniffing(self):
        self.sniffer_running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.NORMAL)  # Enable save button after stopping

    def sniff_packets(self):
        sniff(prn=self.process_packet, store=False)

    def process_packet(self, packet):
        if self.sniffer_running:  # Only add packets if sniffing is active
            self.packets.append(packet)  # Store the packet for later use
            self.packet_display.insert(tk.END, f"{packet.summary()}\n")
            self.packet_display.see(tk.END)  # Scroll to the end

            # Update the Listbox with the new packet summary
            self.packet_listbox.insert(END, packet.summary())

    def save_packets(self):
        # Open a file dialog to choose the file name and location
        pcap_file = filedialog.asksaveasfilename(
            defaultextension=".pcap",  # Ensure the file extension is .pcap
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")],
            title="Save Captured Packets"
        )

        # Check if the user provided a file name
        if pcap_file:
            wrpcap(pcap_file, self.packets)  # Use wrpcap to write packets to a PCAP file
            messagebox.showinfo("Save Packets", f"Packets saved to {pcap_file}")

    def show_packet_details(self, event):
        try:
            # Get the index of the selected packet
            index = self.packet_listbox.curselection()[0]
            packet = self.packets[index]  # Retrieve the corresponding packet

            # Show detailed information about the packet in the details_display area
            details = packet.show(dump=True)  # Use dump=True to show full details
            self.details_display.delete(1.0, tk.END)  # Clear previous details
            self.details_display.insert(tk.END, details)
            self.details_display.config(state=tk.NORMAL)  # Make text editable/readable
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
