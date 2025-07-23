"""
Packet Diff TUI - Terminal-based packet comparison tool.

A tool for comparing two Wireshark capture files (.pcap/.pcapng) with an 
interactive TUI featuring colored highlighting and expandable packet details.
"""

__version__ = "0.1.0"
__author__ = "Packet Diff Contributors"
__email__ = "contributors@pcap-diff.example.com"

from . import models
from .packet_parser import PacketParser
from .packet_differ import PacketDiffer

__all__ = [
    "models",
    "PacketParser", 
    "PacketDiffer",
    "__version__",
]