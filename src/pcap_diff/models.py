"""
Data models for packet diff tool.

This module contains the core data structures used throughout the application
for representing packets, layers, and differences.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from enum import Enum
import time


class DiffType(Enum):
    """Types of differences between packets or fields."""
    UNCHANGED = "unchanged"
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"


@dataclass
class PacketLayer:
    """
    Represents a single protocol layer within a packet.
    
    This is a hierarchical structure where each layer can contain sublayers,
    creating a tree-like representation of the packet structure.
    """
    name: str
    fields: Dict[str, Any] = field(default_factory=dict)
    sublayers: List['PacketLayer'] = field(default_factory=list)
    raw_data: Optional[bytes] = None
    
    def get_field(self, field_name: str, default: Any = None) -> Any:
        """Get a field value with optional default."""
        return self.fields.get(field_name, default)
    
    def has_field(self, field_name: str) -> bool:
        """Check if a field exists in this layer."""
        return field_name in self.fields
    
    def get_all_fields_flat(self) -> Dict[str, Any]:
        """Get all fields from this layer and all sublayers in a flat dict."""
        all_fields = self.fields.copy()
        
        for sublayer in self.sublayers:
            sublayer_fields = sublayer.get_all_fields_flat()
            # Prefix sublayer fields with layer name to avoid conflicts
            for key, value in sublayer_fields.items():
                all_fields[f"{sublayer.name}.{key}"] = value
                
        return all_fields
    
    def find_layer(self, layer_name: str) -> Optional['PacketLayer']:
        """Find a specific layer by name in this layer hierarchy."""
        if self.name.lower() == layer_name.lower():
            return self
            
        for sublayer in self.sublayers:
            found = sublayer.find_layer(layer_name)
            if found:
                return found
                
        return None
    
    def get_summary(self) -> str:
        """Generate a brief summary of this layer."""
        # Common fields that make good summaries
        summary_fields = ['src', 'dst', 'sport', 'dport', 'type', 'proto', 'len']
        
        summary_parts = [self.name]
        for field_name in summary_fields:
            if field_name in self.fields:
                summary_parts.append(f"{field_name}={self.fields[field_name]}")
                
        return " ".join(summary_parts)


@dataclass 
class PacketDiff:
    """
    Represents the difference between two packets.
    
    Contains metadata about the packets being compared and detailed
    information about differences at the layer and field level.
    """
    packet_id: int
    timestamp_1: Optional[float] = None
    timestamp_2: Optional[float] = None  
    diff_type: DiffType = DiffType.UNCHANGED
    layer_diffs: Dict[str, Dict[str, DiffType]] = field(default_factory=dict)
    packet_1: Optional[PacketLayer] = None
    packet_2: Optional[PacketLayer] = None
    similarity_score: float = 0.0
    
    def get_timestamp_diff(self) -> Optional[float]:
        """Get the time difference between packets in seconds."""
        if self.timestamp_1 is not None and self.timestamp_2 is not None:
            return abs(self.timestamp_2 - self.timestamp_1)
        return None
    
    def has_differences(self) -> bool:
        """Check if this packet diff contains any actual differences."""
        return self.diff_type != DiffType.UNCHANGED or bool(self.layer_diffs)
    
    def get_diff_summary(self) -> str:
        """Generate a summary string describing the differences."""
        if self.diff_type == DiffType.ADDED:
            return "Packet added"
        elif self.diff_type == DiffType.REMOVED:
            return "Packet removed"
        elif self.diff_type == DiffType.UNCHANGED:
            return "No differences"
        elif self.diff_type == DiffType.MODIFIED:
            changed_layers = len(self.layer_diffs)
            total_field_changes = sum(len(fields) for fields in self.layer_diffs.values())
            return f"Modified: {changed_layers} layers, {total_field_changes} fields"
        
        return "Unknown difference type"
    
    def get_changed_fields(self) -> List[str]:
        """Get a list of all changed field paths."""
        changed_fields = []
        
        for layer_name, field_diffs in self.layer_diffs.items():
            for field_name, diff_type in field_diffs.items():
                if diff_type != DiffType.UNCHANGED:
                    changed_fields.append(f"{layer_name}.{field_name}")
                    
        return changed_fields


@dataclass
class CaptureMetadata:
    """
    Metadata about a packet capture file.
    
    Contains summary information useful for displaying file details
    and understanding the scope of the capture.
    """
    filename: str
    packet_count: int = 0
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    protocols: List[str] = field(default_factory=list)
    file_size: int = 0
    capture_duration: Optional[float] = None
    
    def get_duration(self) -> Optional[float]:
        """Calculate capture duration in seconds."""
        if self.start_time is not None and self.end_time is not None:
            return self.end_time - self.start_time
        return self.capture_duration
    
    def get_duration_str(self) -> str:
        """Get human-readable duration string."""
        duration = self.get_duration()
        if duration is None:
            return "Unknown"
            
        if duration < 60:
            return f"{duration:.2f}s"
        elif duration < 3600:
            return f"{duration/60:.1f}m"
        else:
            return f"{duration/3600:.1f}h"
    
    def get_file_size_str(self) -> str:
        """Get human-readable file size string."""
        if self.file_size == 0:
            return "Unknown"
            
        size = self.file_size
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f}{unit}"
            size /= 1024
            
        return f"{size:.1f}TB"
    
    def get_summary(self) -> str:
        """Generate a summary string for this capture."""
        return (f"{self.filename}: {self.packet_count} packets, "
                f"{self.get_duration_str()}, {self.get_file_size_str()}")


@dataclass
class ComparisonResult:
    """
    Results of comparing two packet captures.
    
    Contains all the differences found and metadata about the comparison process.
    """
    file1_metadata: CaptureMetadata
    file2_metadata: CaptureMetadata
    packet_diffs: List[PacketDiff] = field(default_factory=list)
    comparison_time: float = field(default_factory=time.time)
    total_packets_1: int = 0
    total_packets_2: int = 0
    identical_packets: int = 0
    modified_packets: int = 0
    added_packets: int = 0
    removed_packets: int = 0
    
    def get_diff_counts(self) -> Dict[DiffType, int]:
        """Get counts of each type of difference."""
        counts = {diff_type: 0 for diff_type in DiffType}
        
        for packet_diff in self.packet_diffs:
            counts[packet_diff.diff_type] += 1
            
        return counts
    
    def get_similarity_percentage(self) -> float:
        """Calculate overall similarity percentage between captures."""
        if not self.packet_diffs:
            return 100.0
            
        total_score = sum(diff.similarity_score for diff in self.packet_diffs)
        return (total_score / len(self.packet_diffs)) * 100
    
    def get_summary(self) -> str:
        """Generate a summary of the comparison results."""
        diff_counts = self.get_diff_counts()
        similarity = self.get_similarity_percentage()
        
        return (f"Comparison: {len(self.packet_diffs)} packets analyzed, "
                f"{similarity:.1f}% similar, "
                f"{diff_counts[DiffType.MODIFIED]} modified, "
                f"{diff_counts[DiffType.ADDED]} added, "
                f"{diff_counts[DiffType.REMOVED]} removed")


# Color scheme constants for diff highlighting
DIFF_COLORS = {
    DiffType.UNCHANGED: ("white", None),      # White text, no background
    DiffType.ADDED: ("white", "green"),       # White on green
    DiffType.REMOVED: ("white", "red"),       # White on red  
    DiffType.MODIFIED: ("black", "yellow"),   # Black on yellow
}

# Common protocol port mappings for enhanced summaries
COMMON_PORTS = {
    80: "HTTP",
    443: "HTTPS", 
    53: "DNS",
    22: "SSH",
    21: "FTP",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    993: "IMAPS",
    995: "POP3S",
    5060: "SIP",
    5061: "SIPS"
}