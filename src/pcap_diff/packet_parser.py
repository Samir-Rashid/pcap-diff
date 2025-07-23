"""
Packet parser module for loading and parsing pcap files.

This module provides functionality to parse packet capture files using pyshark
and convert them into our internal PacketLayer representation.
"""

import pyshark
import asyncio
import logging
from typing import List, Optional, Callable, Dict, Any
from pathlib import Path
import os

from .models import PacketLayer, CaptureMetadata

logger = logging.getLogger(__name__)


class PacketParser:
    """
    Parser for packet capture files using pyshark backend.
    
    Handles loading and parsing of pcap/pcapng files, converting packets
    into our internal representation with caching support.
    """

    def __init__(self):
        self.cache: Dict[str, List[PacketLayer]] = {}
        self._progress_callback: Optional[Callable[[int, int], None]] = None
    
    async def parse_capture(
        self, 
        filepath: str, 
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> List[PacketLayer]:
        """
        Parse pcap file and convert to PacketLayer objects.
        
        Args:
            filepath: Path to the pcap file
            progress_callback: Optional callback for progress updates (current, total)
            
        Returns:
            List of PacketLayer objects representing the packets
            
        Raises:
            FileNotFoundError: If the pcap file doesn't exist
            Exception: If parsing fails
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"PCAP file not found: {filepath}")
        
        # Check cache first
        cache_key = f"{filepath}:{os.path.getmtime(filepath)}"
        if cache_key in self.cache:
            logger.info(f"Using cached packets for {filepath}")
            return self.cache[cache_key]
        
        self._progress_callback = progress_callback
        packets = []
        
        try:
            logger.info(f"Starting to parse {filepath}")
            
            # Open capture with pyshark
            cap = await asyncio.get_event_loop().run_in_executor(
                None, lambda: pyshark.FileCapture(filepath)
            )
            
            # First pass: count total packets for progress
            total_packets = 0
            try:
                # Try to get packet count quickly
                temp_cap = pyshark.FileCapture(filepath)
                for _ in temp_cap:
                    total_packets += 1
                temp_cap.close()
            except Exception as e:
                logger.warning(f"Could not count packets: {e}")
                total_packets = 0
            
            # Second pass: actually parse packets
            current_packet = 0
            
            for packet in cap:
                try:
                    packet_layer = await self._packet_to_layer(packet)
                    packets.append(packet_layer)
                    current_packet += 1
                    
                    # Update progress
                    if progress_callback and total_packets > 0:
                        progress_callback(current_packet, total_packets)
                        
                except Exception as e:
                    logger.warning(f"Failed to parse packet {current_packet}: {e}")
                    # Continue with next packet
                    continue
            
            cap.close()
            
            # Cache the results
            self.cache[cache_key] = packets
            
            logger.info(f"Successfully parsed {len(packets)} packets from {filepath}")
            return packets
            
        except Exception as e:
            logger.error(f"Failed to parse capture {filepath}: {e}")
            raise Exception(f"Failed to parse capture: {e}")
    
    async def _packet_to_layer(self, packet) -> PacketLayer:
        """
        Convert pyshark packet to PacketLayer hierarchy.
        
        Args:
            packet: pyshark packet object
            
        Returns:
            PacketLayer representing the packet structure
        """
        # Create root packet layer
        packet_fields = {
            'number': getattr(packet, 'number', None),
            'timestamp': float(packet.sniff_time.timestamp()) if hasattr(packet, 'sniff_time') else None,
            'length': getattr(packet, 'length', None),
        }
        
        root_layer = PacketLayer(
            name="Packet",
            fields=packet_fields
        )
        
        # Process each layer in the packet
        for layer in packet.layers:
            try:
                layer_obj = self._parse_layer(layer)
                root_layer.sublayers.append(layer_obj)
            except Exception as e:
                logger.warning(f"Failed to parse layer {layer.layer_name}: {e}")
                # Create a minimal layer representation
                error_layer = PacketLayer(
                    name=layer.layer_name or "Unknown",
                    fields={'error': str(e)}
                )
                root_layer.sublayers.append(error_layer)
        
        return root_layer
    
    def _parse_layer(self, layer) -> PacketLayer:
        """
        Parse a single pyshark layer into PacketLayer.
        
        Args:
            layer: pyshark layer object
            
        Returns:
            PacketLayer representation of the layer
        """
        layer_name = layer.layer_name or "Unknown"
        fields = {}
        
        # Extract all fields from the layer
        for field_name in layer.field_names:
            try:
                field_value = getattr(layer, field_name, None)
                
                # Convert field value to appropriate type
                if field_value is not None:
                    # Handle different field types
                    if hasattr(field_value, 'hex_value'):
                        fields[field_name] = field_value.hex_value
                    elif hasattr(field_value, 'int_value'):
                        fields[field_name] = field_value.int_value
                    else:
                        fields[field_name] = str(field_value)
                        
            except Exception as e:
                logger.debug(f"Failed to extract field {field_name}: {e}")
                fields[field_name] = f"<extraction_error: {e}>"
        
        # Get raw data if available
        raw_data = None
        if hasattr(layer, 'raw_value'):
            try:
                raw_data = bytes.fromhex(layer.raw_value)
            except Exception:
                pass
        
        return PacketLayer(
            name=layer_name,
            fields=fields,
            raw_data=raw_data
        )
    
    def extract_metadata(self, packets: List[PacketLayer], filepath: str) -> CaptureMetadata:
        """
        Extract capture statistics and metadata.
        
        Args:
            packets: List of parsed packets
            filepath: Path to the original capture file
            
        Returns:
            CaptureMetadata object with file statistics
        """
        if not packets:
            return CaptureMetadata(
                filename=os.path.basename(filepath),
                file_size=os.path.getsize(filepath) if os.path.exists(filepath) else 0
            )
        
        # Extract timestamps
        timestamps = []
        protocols = set()
        
        for packet in packets:
            # Get timestamp from packet
            timestamp = packet.get_field('timestamp')
            if timestamp:
                timestamps.append(timestamp)
            
            # Collect protocols from layers
            for layer in packet.sublayers:
                protocols.add(layer.name)
        
        # Calculate metadata
        start_time = min(timestamps) if timestamps else None
        end_time = max(timestamps) if timestamps else None
        file_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
        
        return CaptureMetadata(
            filename=os.path.basename(filepath),
            packet_count=len(packets),
            start_time=start_time,
            end_time=end_time,
            protocols=sorted(list(protocols)),
            file_size=file_size
        )
    
    def clear_cache(self) -> None:
        """Clear the packet cache."""
        self.cache.clear()
        logger.info("Packet cache cleared")
    
    def get_cache_info(self) -> Dict[str, int]:
        """Get information about cached files."""
        return {filepath: len(packets) for filepath, packets in self.cache.items()}


# Utility functions for packet parsing
def is_valid_pcap_file(filepath: str) -> bool:
    """
    Check if a file appears to be a valid pcap file.
    
    Args:
        filepath: Path to check
        
    Returns:
        True if file appears to be a valid pcap file
    """
    if not os.path.exists(filepath):
        return False
    
    # Check file extension
    path = Path(filepath)
    if path.suffix.lower() not in ['.pcap', '.pcapng', '.cap']:
        return False
    
    # Check file size (should be at least 24 bytes for pcap header)
    if os.path.getsize(filepath) < 24:
        return False
    
    # Check magic number
    try:
        with open(filepath, 'rb') as f:
            magic = f.read(4)
            # pcap magic numbers (little and big endian)
            pcap_magics = [
                b'\xd4\xc3\xb2\xa1',  # pcap little endian
                b'\xa1\xb2\xc3\xd4',  # pcap big endian
                b'\x0a\x0d\x0d\x0a',  # pcapng
            ]
            return magic in pcap_magics
    except Exception:
        return False


async def quick_packet_count(filepath: str) -> int:
    """
    Quickly count packets in a pcap file without full parsing.
    
    Args:
        filepath: Path to pcap file
        
    Returns:
        Number of packets in the file
    """
    try:
        cap = pyshark.FileCapture(filepath)
        count = 0
        for _ in cap:
            count += 1
        cap.close()
        return count
    except Exception as e:
        logger.error(f"Failed to count packets in {filepath}: {e}")
        return 0