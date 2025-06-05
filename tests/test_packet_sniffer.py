import pytest
import tkinter as tk
import importlib.util
from pathlib import Path
import sys
import types

# Load the PacketSnifferApp from the file with a space in the path
module_path = Path(__file__).resolve().parents[1] / "Packet Sniffer" / "gui_packet_sniffer.py"

# Create stub scapy module if scapy is unavailable
if "scapy.all" not in sys.modules:
    scapy_all = types.ModuleType("scapy.all")

    class DummyAsyncSniffer:
        def __init__(self, *_, **__):
            pass

        def start(self):
            pass

        def stop(self):
            pass

    def wrpcap(*_, **__):
        pass

    scapy_all.AsyncSniffer = DummyAsyncSniffer
    scapy_all.wrpcap = wrpcap
    sys.modules["scapy.all"] = scapy_all

spec = importlib.util.spec_from_file_location("gui_packet_sniffer", module_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
PacketSnifferApp = module.PacketSnifferApp

class DummyPacket:
    def summary(self):
        return "dummy summary"

    def show(self, dump=False):
        return "dummy details"


def create_app():
    try:
        root = tk.Tk()
        root.withdraw()
    except tk.TclError:
        pytest.skip("tkinter not available or no display")
    return PacketSnifferApp(root), root


def test_process_packet_appends_when_running():
    app, root = create_app()
    app.sniffer_running = True
    initial_len = len(app.packets)
    app.process_packet(DummyPacket())
    assert len(app.packets) == initial_len + 1
    root.destroy()


def test_process_packet_no_append_when_not_running():
    app, root = create_app()
    app.sniffer_running = False
    initial_len = len(app.packets)
    app.process_packet(DummyPacket())
    assert len(app.packets) == initial_len
    root.destroy()
