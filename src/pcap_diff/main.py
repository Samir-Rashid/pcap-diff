"""
Main CLI entry point for pcap-diff tool.

This module provides the command-line interface for comparing packet capture files.
"""

import click
import asyncio
import logging
import sys
import json
from pathlib import Path

from .packet_parser import PacketParser, is_valid_pcap_file
from .packet_differ import PacketDiffer

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@click.command()
@click.argument('file1', type=click.Path(exists=True))
@click.argument('file2', type=click.Path(exists=True))
@click.option('--export', '-e', type=click.Choice(['txt', 'html', 'json']), 
              help='Export diff report to file')
@click.option('--time-window', '-t', type=float, default=1.0,
              help='Time window for packet alignment (seconds)')
@click.option('--alignment-threshold', type=float, default=0.8,
              help='Minimum similarity score for packet alignment (0-1)')
@click.option('--no-tui', is_flag=True, help='Run comparison without TUI interface')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
def main(file1, file2, export, time_window, alignment_threshold, no_tui, verbose):
    """
    Compare two packet capture files.
    
    FILE1 and FILE2 should be valid pcap or pcapng files.
    
    Examples:
        pcap-diff capture1.pcap capture2.pcap
        pcap-diff -t 0.5 --export html file1.pcap file2.pcap
        pcap-diff --no-tui --export txt capture1.pcap capture2.pcap
    """
    
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate input files
    if not is_valid_pcap_file(file1):
        click.echo(f"Error: {file1} is not a valid pcap file", err=True)
        sys.exit(1)
    
    if not is_valid_pcap_file(file2):
        click.echo(f"Error: {file2} is not a valid pcap file", err=True)
        sys.exit(1)
    
    if no_tui:
        # Run in CLI mode only
        asyncio.run(run_comparison_only(
            file1, file2, time_window, alignment_threshold, export
        ))
    else:
        # Run TUI application
        try:
            from .tui import run_tui
            asyncio.run(run_tui(file1, file2))
        except ImportError:
            click.echo("TUI mode not available. Running in CLI mode.")
            asyncio.run(run_comparison_only(
                file1, file2, time_window, alignment_threshold, export
            ))


async def run_comparison_only(file1, file2, time_window, alignment_threshold, export_format):
    """
    Run packet comparison without TUI interface.
    
    Args:
        file1: Path to first pcap file
        file2: Path to second pcap file  
        time_window: Time window for alignment
        alignment_threshold: Alignment threshold
        export_format: Export format (txt, html, json, or None)
    """
    try:
        click.echo("Loading packet captures...")
        
        # Initialize parser and differ
        parser = PacketParser()
        differ = PacketDiffer(alignment_threshold, time_window)
        
        # Parse both files
        packets1 = await parser.parse_capture(file1)
        packets2 = await parser.parse_capture(file2)
        
        click.echo(f"Loaded {len(packets1)} packets from {file1}")
        click.echo(f"Loaded {len(packets2)} packets from {file2}")
        
        # Extract metadata
        metadata1 = parser.extract_metadata(packets1, file1)
        metadata2 = parser.extract_metadata(packets2, file2)
        
        click.echo(f"File 1: {metadata1.get_summary()}")
        click.echo(f"File 2: {metadata2.get_summary()}")
        
        # Run comparison
        click.echo("Comparing packets...")
        result = differ.compare_captures(packets1, packets2, metadata1, metadata2)
        
        # Display results
        click.echo("\n" + "="*60)
        click.echo("COMPARISON RESULTS")
        click.echo("="*60)
        click.echo(result.get_summary())
        
        diff_counts = result.get_diff_counts()
        click.echo(f"\nDetailed breakdown:")
        for diff_type, count in diff_counts.items():
            click.echo(f"  {diff_type.value.title()} packets: {count}")
        
        # Show sample differences
        modified_diffs = [d for d in result.packet_diffs if d.has_differences()]
        if modified_diffs:
            click.echo(f"\nSample differences (showing first 10):")
            for i, diff in enumerate(modified_diffs[:10]):
                click.echo(f"  Packet {diff.packet_id}: {diff.get_diff_summary()}")
                if diff.layer_diffs:
                    for layer_name, field_diffs in diff.layer_diffs.items():
                        changed_fields = list(field_diffs.keys())
                        if changed_fields:
                            click.echo(f"    {layer_name}: {', '.join(changed_fields[:3])}")
        
        # Export results if requested
        if export_format:
            export_filename = f"pcap_diff_report.{export_format}"
            click.echo(f"\nExporting results to {export_filename}...")
            
            try:
                export_report(result, export_filename, export_format)
                click.echo(f"Report exported successfully to {export_filename}")
            except Exception as e:
                click.echo(f"Error exporting report: {e}", err=True)
        
    except Exception as e:
        click.echo(f"Error during comparison: {e}", err=True)
        if logger.isEnabledFor(logging.DEBUG):
            import traceback
            traceback.print_exc()
        sys.exit(1)


def export_report(result, filename, format_type):
    """
    Export comparison results to file.
    
    Args:
        result: ComparisonResult object
        filename: Output filename
        format_type: Export format (txt, html, json)
    """
    if format_type == 'txt':
        export_text_report(result, filename)
    elif format_type == 'html':
        export_html_report(result, filename)
    elif format_type == 'json':
        export_json_report(result, filename)
    else:
        raise ValueError(f"Unsupported export format: {format_type}")


def export_text_report(result, filename):
    """Export results as plain text report."""
    with open(filename, 'w') as f:
        f.write("PCAP DIFF REPORT\n")
        f.write("="*50 + "\n\n")
        
        f.write(f"File 1: {result.file1_metadata.get_summary()}\n")
        f.write(f"File 2: {result.file2_metadata.get_summary()}\n\n")
        
        f.write(f"Comparison: {result.get_summary()}\n\n")
        
        diff_counts = result.get_diff_counts()
        f.write("Breakdown:\n")
        for diff_type, count in diff_counts.items():
            f.write(f"  {diff_type.value.title()}: {count}\n")
        
        f.write("\nDetailed Differences:\n")
        f.write("-" * 30 + "\n")
        
        for diff in result.packet_diffs:
            if diff.has_differences():
                f.write(f"\nPacket {diff.packet_id}: {diff.get_diff_summary()}\n")
                for layer_name, field_diffs in diff.layer_diffs.items():
                    f.write(f"  Layer {layer_name}:\n")
                    for field_name, diff_type in field_diffs.items():
                        f.write(f"    {field_name}: {diff_type.value}\n")


def export_html_report(result, filename):
    """Export results as HTML report."""
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>PCAP Diff Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
            .summary {{ margin: 20px 0; }}
            .diff-added {{ background-color: #d4edda; }}
            .diff-removed {{ background-color: #f8d7da; }}
            .diff-modified {{ background-color: #fff3cd; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>PCAP Diff Report</h1>
            <p><strong>File 1:</strong> {result.file1_metadata.get_summary()}</p>
            <p><strong>File 2:</strong> {result.file2_metadata.get_summary()}</p>
        </div>
        
        <div class="summary">
            <h2>Summary</h2>
            <p>{result.get_summary()}</p>
        </div>
        
        <h2>Detailed Differences</h2>
        <table>
            <tr>
                <th>Packet ID</th>
                <th>Type</th>
                <th>Summary</th>
                <th>Changed Fields</th>
            </tr>
    """
    
    for diff in result.packet_diffs:
        if diff.has_differences():
            css_class = f"diff-{diff.diff_type.value}"
            changed_fields = []
            for layer_name, field_diffs in diff.layer_diffs.items():
                for field_name in field_diffs.keys():
                    changed_fields.append(f"{layer_name}.{field_name}")
            
            html_content += f"""
            <tr class="{css_class}">
                <td>{diff.packet_id}</td>
                <td>{diff.diff_type.value.title()}</td>
                <td>{diff.get_diff_summary()}</td>
                <td>{', '.join(changed_fields[:10])}</td>
            </tr>
            """
    
    html_content += """
        </table>
    </body>
    </html>
    """
    
    with open(filename, 'w') as f:
        f.write(html_content)


def export_json_report(result, filename):           
    """Export results as JSON report."""
    # Convert result to JSON-serializable format
    json_data = {
        'file1_metadata': {
            'filename': result.file1_metadata.filename,
            'packet_count': result.file1_metadata.packet_count,
            'file_size': result.file1_metadata.file_size,
            'protocols': result.file1_metadata.protocols,
            'duration': result.file1_metadata.get_duration_str()
        },
        'file2_metadata': {
            'filename': result.file2_metadata.filename,
            'packet_count': result.file2_metadata.packet_count,
            'file_size': result.file2_metadata.file_size,
            'protocols': result.file2_metadata.protocols,
            'duration': result.file2_metadata.get_duration_str()
        },
        'comparison_summary': result.get_summary(),
        'diff_counts': {dt.value: count for dt, count in result.get_diff_counts().items()},
        'packet_diffs': []
    }
    
    # Add packet differences
    for diff in result.packet_diffs:
        if diff.has_differences():
            diff_data = {
                'packet_id': diff.packet_id,
                'diff_type': diff.diff_type.value,
                'summary': diff.get_diff_summary(),
                'similarity_score': diff.similarity_score,
                'layer_diffs': {}
            }
            
            for layer_name, field_diffs in diff.layer_diffs.items():
                diff_data['layer_diffs'][layer_name] = {
                    field_name: diff_type.value 
                    for field_name, diff_type in field_diffs.items()
                }
            
            json_data['packet_diffs'].append(diff_data)
    
    with open(filename, 'w') as f:
        json.dump(json_data, f, indent=2)


if __name__ == "__main__":
    main()