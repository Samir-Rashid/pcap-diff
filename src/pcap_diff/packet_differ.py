"""
Packet comparison and diff algorithm implementation.

This module provides functionality to compare two sets of packets and
generate detailed difference information.
"""

import logging
from typing import List, Tuple, Optional, Dict, Any
import time

from .models import PacketLayer, PacketDiff, DiffType, ComparisonResult, CaptureMetadata

logger = logging.getLogger(__name__)


class PacketDiffer:
    """
    Engine for comparing packet captures and generating diffs.
    
    Implements various alignment algorithms and comparison strategies
    to find differences between packet captures.
    """
    
    def __init__(self, alignment_threshold: float = 0.8, time_window: float = 1.0):
        """
        Initialize the PacketDiffer.
        
        Args:
            alignment_threshold: Minimum similarity score for packet alignment (0-1)
            time_window: Maximum time difference for timestamp-based alignment (seconds)
        """
        self.alignment_threshold = alignment_threshold
        self.time_window = time_window
        self.ignore_fields = {
            # Fields that commonly differ between captures but aren't meaningful
            'frame.time_epoch',
            'frame.time_delta', 
            'frame.time_relative',
            'frame.number',
            'ip.checksum',
            'tcp.checksum',
            'udp.checksum',
            'icmp.checksum',
        }
    
    def compare_captures(
        self,
        packets1: List[PacketLayer], 
        packets2: List[PacketLayer],
        metadata1: CaptureMetadata,
        metadata2: CaptureMetadata
    ) -> ComparisonResult:
        """
        Main diff algorithm for comparing two packet captures.
        
        Args:
            packets1: Packets from first capture
            packets2: Packets from second capture
            metadata1: Metadata for first capture
            metadata2: Metadata for second capture
            
        Returns:
            ComparisonResult containing all differences
        """
        logger.info(f"Comparing {len(packets1)} vs {len(packets2)} packets")
        start_time = time.time()
        
        # Align packets using best-match algorithm
        alignments = self.align_packets(packets1, packets2)
        
        # Compare aligned packets
        packet_diffs = []
        for i, (idx1, idx2) in enumerate(alignments):
            if idx1 is not None and idx2 is not None:
                # Both packets exist - compare them
                diff = self._compare_packets(
                    packets1[idx1], packets2[idx2], i
                )
            elif idx1 is not None:
                # Packet only in capture 1 - removed
                diff = PacketDiff(
                    packet_id=i,
                    timestamp_1=packets1[idx1].get_field('timestamp'),
                    diff_type=DiffType.REMOVED,
                    packet_1=packets1[idx1],
                    similarity_score=0.0
                )
            else:
                # Packet only in capture 2 - added
                if idx2 is not None:
                    diff = PacketDiff(
                        packet_id=i,
                        timestamp_2=packets2[idx2].get_field('timestamp'),
                        diff_type=DiffType.ADDED,
                        packet_2=packets2[idx2],
                        similarity_score=0.0
                    )
                else:
                    # This shouldn't happen given the alignment logic, but handle it
                    diff = PacketDiff(
                        packet_id=i,
                        diff_type=DiffType.REMOVED,
                        similarity_score=0.0
                    )
            
            packet_diffs.append(diff)
        
        # Calculate summary statistics
        diff_counts = {}
        for diff_type in DiffType:
            diff_counts[diff_type] = sum(1 for diff in packet_diffs if diff.diff_type == diff_type)
        
        comparison_time = time.time() - start_time
        logger.info(f"Comparison completed in {comparison_time:.2f}s")
        
        return ComparisonResult(
            file1_metadata=metadata1,
            file2_metadata=metadata2,
            packet_diffs=packet_diffs,
            comparison_time=comparison_time,
            total_packets_1=len(packets1),
            total_packets_2=len(packets2),
            identical_packets=diff_counts[DiffType.UNCHANGED],
            modified_packets=diff_counts[DiffType.MODIFIED],
            added_packets=diff_counts[DiffType.ADDED],
            removed_packets=diff_counts[DiffType.REMOVED]
        )
    
    def align_packets(
        self, 
        packets1: List[PacketLayer], 
        packets2: List[PacketLayer]
    ) -> List[Tuple[Optional[int], Optional[int]]]:
        """
        Packet alignment algorithm using timestamp-based approach.
        
        Args:
            packets1: Packets from first capture
            packets2: Packets from second capture
            
        Returns:
            List of (index1, index2) tuples representing packet alignment
        """
        logger.info("Aligning packets using timestamp-based algorithm")
        
        # Extract timestamps
        timestamps1 = []
        timestamps2 = []
        
        for i, packet in enumerate(packets1):
            ts = packet.get_field('timestamp')
            if ts is not None:
                timestamps1.append((ts, i))
        
        for i, packet in enumerate(packets2):
            ts = packet.get_field('timestamp')
            if ts is not None:
                timestamps2.append((ts, i))
        
        # Sort by timestamp
        timestamps1.sort()
        timestamps2.sort()
        
        # Align packets within time window
        alignments = []
        used1 = set()
        used2 = set()
        
        # For each packet in capture 1, find best match in capture 2
        for ts1, idx1 in timestamps1:
            best_match = None
            best_diff = float('inf')
            
            for ts2, idx2 in timestamps2:
                if idx2 in used2:
                    continue
                    
                time_diff = abs(ts2 - ts1)
                if time_diff <= self.time_window and time_diff < best_diff:
                    best_diff = time_diff
                    best_match = idx2
            
            if best_match is not None:
                alignments.append((idx1, best_match))
                used1.add(idx1)
                used2.add(best_match)
            else:
                alignments.append((idx1, None))  # Removed packet
        
        # Add any unmatched packets from capture 2 as added
        for ts2, idx2 in timestamps2:
            if idx2 not in used2:
                alignments.append((None, idx2))  # Added packet
        
        logger.info(f"Aligned {len(alignments)} packet pairs")
        return alignments
    
    def _compare_packets(
        self, 
        packet1: PacketLayer, 
        packet2: PacketLayer, 
        packet_id: int
    ) -> PacketDiff:
        """
        Compare two aligned packets and generate difference information.
        
        Args:
            packet1: First packet
            packet2: Second packet
            packet_id: Unique identifier for this packet comparison
            
        Returns:
            PacketDiff object containing difference information
        """
        # Compare layers
        layer_diffs = self.compare_layers(packet1, packet2)
        
        # Calculate similarity score
        similarity = self.calculate_similarity(packet1, packet2)
        
        # Determine overall diff type
        if not layer_diffs:
            diff_type = DiffType.UNCHANGED
        else:
            diff_type = DiffType.MODIFIED
        
        return PacketDiff(
            packet_id=packet_id,
            timestamp_1=packet1.get_field('timestamp'),
            timestamp_2=packet2.get_field('timestamp'),
            diff_type=diff_type,
            layer_diffs=layer_diffs,
            packet_1=packet1,
            packet_2=packet2,
            similarity_score=similarity
        )
    
    def compare_layers(
        self, 
        packet1: PacketLayer, 
        packet2: PacketLayer
    ) -> Dict[str, Dict[str, DiffType]]:
        """
        Deep comparison of packet layers.
        
        Args:
            packet1: First packet layer hierarchy
            packet2: Second packet layer hierarchy
            
        Returns:
            Nested dict of layer -> field -> DiffType differences
        """
        layer_diffs = {}
        
        # Get all layers from both packets
        layers1 = {layer.name: layer for layer in packet1.sublayers}
        layers2 = {layer.name: layer for layer in packet2.sublayers}
        
        all_layer_names = set(layers1.keys()) | set(layers2.keys())
        
        for layer_name in all_layer_names:
            layer1 = layers1.get(layer_name)
            layer2 = layers2.get(layer_name)
            
            field_diffs = {}
            
            if layer1 is None:
                # Layer only in packet2 - added
                if layer2:
                    for field_name in layer2.fields:
                        field_diffs[field_name] = DiffType.ADDED
            elif layer2 is None:
                # Layer only in packet1 - removed
                for field_name in layer1.fields:
                    field_diffs[field_name] = DiffType.REMOVED
            else:
                # Both layers exist - compare fields
                field_diffs = self._compare_layer_fields(layer1, layer2)
            
            if field_diffs:
                layer_diffs[layer_name] = field_diffs
        
        return layer_diffs
    
    def _compare_layer_fields(
        self, 
        layer1: PacketLayer, 
        layer2: PacketLayer
    ) -> Dict[str, DiffType]:
        """
        Compare fields between two layers.
        
        Args:
            layer1: First layer
            layer2: Second layer
            
        Returns:
            Dict of field_name -> DiffType differences
        """
        field_diffs = {}
        
        all_field_names = set(layer1.fields.keys()) | set(layer2.fields.keys())
        
        for field_name in all_field_names:
            # Skip ignored fields
            if field_name in self.ignore_fields:
                continue
                
            value1 = layer1.fields.get(field_name)
            value2 = layer2.fields.get(field_name)
            
            if value1 is None and value2 is not None:
                field_diffs[field_name] = DiffType.ADDED
            elif value1 is not None and value2 is None:
                field_diffs[field_name] = DiffType.REMOVED
            elif value1 != value2:
                field_diffs[field_name] = DiffType.MODIFIED
            # If values are equal, no diff (UNCHANGED)
        
        return field_diffs
    
    def calculate_similarity(self, packet1: PacketLayer, packet2: PacketLayer) -> float:
        """
        Calculate similarity score between packets (0-1).
        
        Args:
            packet1: First packet
            packet2: Second packet
            
        Returns:
            Similarity score from 0.0 (completely different) to 1.0 (identical)
        """
        # Get all fields from both packets
        fields1 = packet1.get_all_fields_flat()
        fields2 = packet2.get_all_fields_flat()
        
        # Filter out ignored fields
        fields1 = {k: v for k, v in fields1.items() if k not in self.ignore_fields}
        fields2 = {k: v for k, v in fields2.items() if k not in self.ignore_fields}
        
        all_fields = set(fields1.keys()) | set(fields2.keys())
        
        if not all_fields:
            return 1.0  # Both packets have no comparable fields
        
        matching_fields = 0
        for field_name in all_fields:
            value1 = fields1.get(field_name)
            value2 = fields2.get(field_name)
            
            if value1 == value2:
                matching_fields += 1
        
        return matching_fields / len(all_fields)