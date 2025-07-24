# pcap-diff

Terminal-based packet diff tool for comparing Wireshark capture files.

## Installation

```
nix develop
```

```
nix develop .#impure
uv sync
```

## Usage

```bash
pcap-diff file1.pcap file2.pcap
```





### **1. Packet Parser ([`packet_parser.py`](src/pcap_diff/packet_parser.py:1))**
- Thread-based parsing using PyShark to avoid asyncio conflicts
- Supports `.pcap`, `.pcapng`, and `.cap` files
- Validates files using magic number detection
- Extracts hierarchical packet layer structures
- Implements caching for performance optimization
- Handles errors gracefully with detailed logging

### **2. Data Models ([`models.py`](src/pcap_diff/models.py:1))**
- [`PacketLayer`](src/pcap_diff/models.py:23) - Hierarchical packet representation
- [`PacketDiff`](src/pcap_diff/models.py:81) - Difference tracking between packets
- [`DiffType`](src/pcap_diff/models.py:14) - Enumeration of difference types (UNCHANGED, ADDED, REMOVED, MODIFIED)
- [`CaptureMetadata`](src/pcap_diff/models.py:135) - File statistics and metadata
- [`ComparisonResult`](src/pcap_diff/models.py:189) - Complete comparison results with summary statistics

### **3. Diff Algorithm ([`packet_differ.py`](src/pcap_diff/packet_differ.py:1))**
- Timestamp-based packet alignment with configurable time window
- Deep layer-by-layer field comparison
- Similarity scoring (0-1 scale)
- Configurable field filtering (ignores checksums, timestamps, etc.)
- Flow-based alignment for accurate packet matching

### **4. Terminal User Interface ([`tui.py`](src/pcap_diff/tui.py:1))**
- Built with Textual framework for modern terminal UI
- DataTable widget for packet list with color coding
- Detailed packet information panel
- Keyboard navigation (up/down, row selection)
- Real-time loading progress indicators
- Responsive layout with proper error handling

### **5. Command Line Interface ([`main.py`](src/pcap_diff/main.py:1))**
- Comprehensive CLI with Click framework
- Support for both TUI and non-interactive modes
- Configurable alignment parameters (time window, similarity threshold)
- Multiple export formats: TXT, HTML, JSON
- Verbose logging options
- File validation and error handling

## **Export Functionality**
## 🚀 **Usage Examples**

```bash
# Interactive TUI mode
python -m pcap_diff.main capture1.pcap capture2.pcap

# CLI mode with text export
python -m pcap_diff.main --no-tui --export txt file1.pcap file2.pcap

# Custom alignment parameters
python -m pcap_diff.main -t 0.5 --alignment-threshold 0.9 --export html capture1.pcap capture2.pcap
```
