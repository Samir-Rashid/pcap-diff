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
import concurrent.futures
import threading

from .models import PacketLayer, CaptureMetadata

logger = logging.getLogger(__name__)


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


def _parse_pcap_in_thread(filepath: str) -> List[PacketLayer]:
    """
    Parse PCAP file in a separate thread to avoid event loop conflicts.
    
    Args:
        filepath: Path to PCAP file
        
    Returns:
        List of parsed PacketLayer objects
    """
    packets = []
    
    try:
        # Create capture in thread without event loop conflicts
        capture = pyshark.FileCapture(filepath)
        
        packet_count = 0
        for packet in capture:
            try:
                # Create root packet layer with basic info
                packet_fields = {}
                
                # Extract basic packet info
                if hasattr(packet, 'number'):
                    packet_fields['number'] = str(packet.number)
                
                if hasattr(packet, 'sniff_time'):
                    packet_fields['timestamp'] = float(packet.sniff_time.timestamp())
                
                if hasattr(packet, 'length'):
                    packet_fields['length'] = str(packet.length)
                
                root_layer = PacketLayer(
                    name="Packet",
                    fields=packet_fields
                )
                
                # Process each layer in the packet
                for layer in packet.layers:
                    try:
                        layer_name = getattr(layer, 'layer_name', 'Unknown')
                        fields = {}
                        
                        # Extract all fields from the layer
                        if hasattr(layer, 'field_names'):
                            for field_name in layer.field_names:
                                try:
                                    field_value = getattr(layer, field_name, None)
                                    
                                    # Convert field value to string
                                    if field_value is not None:
                                        fields[field_name] = str(field_value)
                                        
                                except Exception as e:
                                    logger.debug(f"Failed to extract field {field_name}: {e}")
                                    fields[field_name] = f"<extraction_error: {e}>"
                        
                        layer_obj = PacketLayer(
                            name=layer_name,
                            fields=fields
                        )
                        
                        if layer_obj:
                            root_layer.sublayers.append(layer_obj)
                            
                    except Exception as e:
                        logger.debug(f"Failed to parse layer {getattr(layer, 'layer_name', 'Unknown')}: {e}")
                        # Create a minimal layer representation
                        error_layer = PacketLayer(
                            name=getattr(layer, 'layer_name', 'Unknown'),
                            fields={'error': str(e)}
                        )
                        root_layer.sublayers.append(error_layer)
                
                packets.append(root_layer)
                packet_count += 1
                
                if packet_count % 100 == 0:
                    logger.debug(f"Parsed {packet_count} packets")
                    
            except Exception as e:
                logger.warning(f"Failed to parse packet {packet_count}: {e}")
                continue
                
        capture.close()
        
    except Exception as e:
        logger.error(f"Failed to parse capture {filepath}: {e}")
        raise ValueError(f"Failed to parse capture: {e}")
    
    return packets


class PacketParser:
    """
    Parser for packet capture files using pyshark backend.
    
    Handles loading and parsing of pcap/pcapng files, converting packets
    into our internal representation with caching support.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._cache: Dict[str, List[PacketLayer]] = {}
    
    async def parse_capture(self, filepath: str) -> List[PacketLayer]:
        """
        Parse a capture file and return list of packet structures.
        
        Args:
            filepath: Path to the PCAP file
            
        Returns:
            List of parsed packet layers
            
        Raises:
            ValueError: If file cannot be parsed
        """
        if not is_valid_pcap_file(filepath):
            raise ValueError(f"Invalid PCAP file: {filepath}")
        
        try:
            self.logger.info(f"Starting to parse {filepath}")
            
            # Check cache first
            cache_key = f"{filepath}:{os.path.getmtime(filepath)}"
            if cache_key in self._cache:
                self.logger.info(f"Using cached data for {filepath}")
                return self._cache[cache_key]
            
            # Run parsing in a separate thread to avoid event loop conflicts
            loop = asyncio.get_event_loop()
            with concurrent.futures.ThreadPoolExecutor() as executor:
                packets = await loop.run_in_executor(
                    executor, _parse_pcap_in_thread, filepath
                )
            
            self.logger.info(f"Successfully parsed {len(packets)} packets from {filepath}")
            
            # Cache the results
            self._cache[cache_key] = packets
            
            return packets
            
        except Exception as e:
            self.logger.error(f"Failed to parse capture {filepath}: {e}")
            raise ValueError(f"Failed to parse capture: {e}")
    
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
        self._cache.clear()
        self.logger.info("Packet cache cleared")
    
    def get_cache_info(self) -> Dict[str, int]:
        """Get information about cached files."""
        return {filepath: len(packets) for filepath, packets in self._cache.items()}