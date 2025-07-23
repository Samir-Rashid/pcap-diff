"""
Terminal User Interface for packet diff visualization.

This module provides the Textual-based TUI for interactive packet comparison.
"""

import asyncio
from typing import List, Optional
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Tree, Static, DataTable, Label
from textual.reactive import reactive
from textual import log
from rich.text import Text
from rich.syntax import Syntax

from .models import ComparisonResult, PacketDiff, DiffType
from .packet_parser import PacketParser
from .packet_differ import PacketDiffer


class PacketDiffApp(App):
    """Main TUI application for packet comparison."""
    
    TITLE = "PCAP Diff Tool"
    
    # Reactive attributes
    current_diff_index = reactive(0)
    comparison_result: Optional[ComparisonResult] = None
    
    def __init__(self, file1: str, file2: str, **kwargs):
        super().__init__(**kwargs)
        self.file1 = file1
        self.file2 = file2
        self.packet_diffs: List[PacketDiff] = []
        
    def compose(self) -> ComposeResult:
        """Create the TUI layout."""
        yield Header()
        
        with Container(id="main-container"):
            with Horizontal():
                # Left panel - packet list
                with Vertical(id="packet-list-panel"):
                    yield Label("Packet Differences", id="packet-list-header")
                    yield DataTable(id="packet-table")
                
                # Right panel - packet details
                with Vertical(id="packet-details-panel"):
                    yield Label("Packet Details", id="packet-details-header")
                    with Container(id="packet-details"):
                        yield Static("Select a packet to view details", id="packet-info")
        
        yield Footer()
    
    def on_mount(self) -> None:
        """Initialize the application."""
        self.title = f"PCAP Diff: {Path(self.file1).name} vs {Path(self.file2).name}"
        
        # Set up the packet table
        table = self.query_one("#packet-table", DataTable)
        table.add_columns("ID", "Type", "Summary", "Similarity")
        table.cursor_type = "row"
        table.zebra_stripes = True
        
        # Load data asynchronously
        self.call_after_refresh(self._load_data)
    
    async def _load_data(self) -> None:
        """Load and compare packet captures."""
        try:
            # Show loading message
            info_widget = self.query_one("#packet-info", Static)
            info_widget.update("Loading packet captures...")
            
            # Initialize parser and differ
            parser = PacketParser()
            differ = PacketDiffer()
            
            # Parse both files
            packets1 = await parser.parse_capture(self.file1)
            packets2 = await parser.parse_capture(self.file2)
            
            info_widget.update(f"Comparing {len(packets1)} vs {len(packets2)} packets...")
            
            # Extract metadata and compare
            metadata1 = parser.extract_metadata(packets1, self.file1)
            metadata2 = parser.extract_metadata(packets2, self.file2)
            
            self.comparison_result = differ.compare_captures(
                packets1, packets2, metadata1, metadata2
            )
            
            # Filter to only show packets with differences
            self.packet_diffs = [
                diff for diff in self.comparison_result.packet_diffs 
                if diff.has_differences()
            ]
            
            # Populate the table
            self._populate_packet_table()
            
            # Update info display
            if self.packet_diffs:
                self._show_packet_details(0)
            else:
                info_widget.update("No differences found between the packet captures.")
                
        except Exception as e:
            log.error(f"Error loading data: {e}")
            info_widget = self.query_one("#packet-info", Static)
            info_widget.update(f"Error: {str(e)}")
    
    def _populate_packet_table(self) -> None:
        """Populate the packet differences table."""
        table = self.query_one("#packet-table", DataTable)
        table.clear()
        
        for i, diff in enumerate(self.packet_diffs):
            # Color code by diff type
            if diff.diff_type == DiffType.ADDED:
                style = "green"
            elif diff.diff_type == DiffType.REMOVED:
                style = "red"
            elif diff.diff_type == DiffType.MODIFIED:
                style = "yellow"
            else:
                style = "white"
            
            table.add_row(
                str(diff.packet_id),
                diff.diff_type.value.title(),
                diff.get_diff_summary()[:50] + "..." if len(diff.get_diff_summary()) > 50 else diff.get_diff_summary(),
                f"{diff.similarity_score:.2f}" if diff.similarity_score is not None else "N/A",
                key=str(i)
            )
    
    def _show_packet_details(self, diff_index: int) -> None:
        """Show detailed information for a specific packet diff."""
        if not (0 <= diff_index < len(self.packet_diffs)):
            return
            
        diff = self.packet_diffs[diff_index]
        info_widget = self.query_one("#packet-info", Static)
        
        # Build detailed diff information
        details = []
        details.append(f"Packet ID: {diff.packet_id}")
        details.append(f"Diff Type: {diff.diff_type.value.title()}")
        details.append(f"Similarity: {diff.similarity_score:.2f}" if diff.similarity_score is not None else "Similarity: N/A")
        
        if diff.timestamp_1 and diff.timestamp_2:
            details.append(f"Timestamp 1: {diff.timestamp_1}")
            details.append(f"Timestamp 2: {diff.timestamp_2}")
        
        details.append("")
        details.append("Layer Differences:")
        
        if diff.layer_diffs:
            for layer_name, field_diffs in diff.layer_diffs.items():
                details.append(f"  {layer_name}:")
                for field_name, field_diff_type in field_diffs.items():
                    details.append(f"    {field_name}: {field_diff_type.value}")
        else:
            details.append("  No specific layer differences found")
        
        # Show packet data if available
        if diff.packet_1 or diff.packet_2:
            details.append("")
            details.append("Packet Data:")
            
            if diff.packet_1:
                details.append("  Packet 1 layers:")
                for layer in diff.packet_1.sublayers:
                    details.append(f"    - {layer.name}")
            
            if diff.packet_2:
                details.append("  Packet 2 layers:")
                for layer in diff.packet_2.sublayers:
                    details.append(f"    - {layer.name}")
        
        info_widget.update("\n".join(details))
    
    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle packet selection in the table."""
        if event.row_key is not None:
            diff_index = int(event.row_key.value)
            self.current_diff_index = diff_index
            self._show_packet_details(diff_index)
    
    def action_quit(self) -> None:
        """Quit the application."""
        self.exit()
    
    def action_next_diff(self) -> None:
        """Navigate to next difference."""
        if self.packet_diffs and self.current_diff_index < len(self.packet_diffs) - 1:
            self.current_diff_index += 1
            table = self.query_one("#packet-table", DataTable)
            table.move_cursor(row=self.current_diff_index)
            self._show_packet_details(self.current_diff_index)
    
    def action_prev_diff(self) -> None:
        """Navigate to previous difference."""
        if self.packet_diffs and self.current_diff_index > 0:
            self.current_diff_index -= 1
            table = self.query_one("#packet-table", DataTable)
            table.move_cursor(row=self.current_diff_index)
            self._show_packet_details(self.current_diff_index)


async def run_tui(file1: str, file2: str) -> None:
    """Run the TUI application."""
    app = PacketDiffApp(file1, file2)
    await app.run_async()


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python -m pcap_diff.tui <file1> <file2>")
        sys.exit(1)
    
    asyncio.run(run_tui(sys.argv[1], sys.argv[2]))