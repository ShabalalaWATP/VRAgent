#!/usr/bin/env python3
"""
Binary Analyzer - Terminal User Interface (TUI)
Interactive terminal-based GUI for binary analysis using Rich library
"""

import asyncio
import os
import sys
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
    from rich.prompt import Prompt, Confirm
    from rich.layout import Layout
    from rich.live import Live
    from rich.text import Text
    from rich.tree import Tree
    from rich.markdown import Markdown
    from rich import box
except ImportError:
    print("ERROR: 'rich' library not installed. Install it with: pip install rich")
    sys.exit(1)

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from backend.services.reverse_engineering_service import (
    analyze_binary_with_lief,
    analyze_binary_with_ghidra,
    scan_with_yara_rules,
)


class BinaryAnalyzerTUI:
    """Interactive Terminal User Interface for binary analysis"""

    def __init__(self):
        self.console = Console()
        self.results: Dict[str, Any] = {}

    def show_banner(self):
        """Display welcome banner"""
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║          🔬 VRAgent Binary Analyzer - TUI Mode 🔬            ║
║                                                               ║
║          Interactive Terminal-Based Binary Analysis           ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
        """
        self.console.print(banner, style="bold cyan")
        self.console.print()

    def show_main_menu(self) -> str:
        """Display main menu and get user choice"""
        menu = Table(show_header=False, box=box.ROUNDED, border_style="cyan")
        menu.add_column("Option", style="bold yellow", width=10)
        menu.add_column("Description", style="white")

        menu.add_row("1", "Quick Analysis (Fast, basic info)")
        menu.add_row("2", "Standard Analysis (Comprehensive)")
        menu.add_row("3", "Deep Analysis (Full decompilation + YARA)")
        menu.add_row("4", "View Previous Results")
        menu.add_row("5", "Export Results")
        menu.add_row("6", "Settings")
        menu.add_row("q", "Quit")

        self.console.print(Panel(menu, title="[bold cyan]Main Menu[/bold cyan]", border_style="cyan"))
        self.console.print()

        choice = Prompt.ask(
            "[bold cyan]Select option[/bold cyan]",
            choices=["1", "2", "3", "4", "5", "6", "q"],
            default="2"
        )
        return choice

    def select_binary_file(self) -> Optional[Path]:
        """Prompt user to select a binary file"""
        self.console.print("\n[bold cyan]📂 Select Binary File[/bold cyan]\n")

        while True:
            file_path = Prompt.ask(
                "Enter the path to the binary file",
                default="example.exe"
            )

            path = Path(file_path)
            if path.exists() and path.is_file():
                # Show file info
                stat = path.stat()
                info_table = Table(show_header=False, box=box.SIMPLE)
                info_table.add_column("Property", style="cyan")
                info_table.add_column("Value", style="white")

                info_table.add_row("File Name", path.name)
                info_table.add_row("Size", f"{stat.st_size:,} bytes ({stat.st_size / (1024*1024):.2f} MB)")
                info_table.add_row("Modified", datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"))

                self.console.print(Panel(info_table, title="File Information", border_style="green"))

                if Confirm.ask("Proceed with this file?", default=True):
                    return path
            else:
                self.console.print(f"[bold red]❌ File not found: {file_path}[/bold red]")
                if not Confirm.ask("Try again?", default=True):
                    return None

    async def run_quick_analysis(self, binary_path: Path):
        """Run quick analysis (fast, basic info)"""
        self.console.print("\n[bold cyan]⚡ Running Quick Analysis...[/bold cyan]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=self.console
        ) as progress:

            task = progress.add_task("[cyan]Analyzing binary metadata...", total=100)

            # Basic file analysis
            progress.update(task, advance=30, description="[cyan]Parsing PE/ELF headers...")
            try:
                metadata, _, _, _, _ = await asyncio.to_thread(
                    analyze_binary_with_lief,
                    str(binary_path)
                )
                progress.update(task, advance=40, description="[cyan]Extracting metadata...")

                self.results['metadata'] = metadata

                progress.update(task, advance=30, description="[green]Analysis complete!")

            except Exception as e:
                progress.update(task, description=f"[red]Error: {str(e)}")
                return

        self.display_metadata_results()

    async def run_standard_analysis(self, binary_path: Path):
        """Run standard analysis (comprehensive)"""
        self.console.print("\n[bold cyan]🔍 Running Standard Analysis...[/bold cyan]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=self.console
        ) as progress:

            task = progress.add_task("[cyan]Starting analysis...", total=100)

            try:
                # LIEF analysis
                progress.update(task, advance=20, description="[cyan]Parsing binary structure...")
                metadata, symbols, imports, exports, elf_info = await asyncio.to_thread(
                    analyze_binary_with_lief,
                    str(binary_path)
                )

                self.results['metadata'] = metadata
                self.results['symbols'] = symbols
                self.results['imports'] = imports
                self.results['exports'] = exports

                # YARA scan
                progress.update(task, advance=30, description="[cyan]Running YARA scan...")
                yara_results = await asyncio.to_thread(
                    scan_with_yara_rules,
                    str(binary_path)
                )
                self.results['yara'] = yara_results

                progress.update(task, advance=50, description="[green]Analysis complete!")

            except Exception as e:
                progress.update(task, description=f"[red]Error: {str(e)}")
                return

        self.display_standard_results()

    async def run_deep_analysis(self, binary_path: Path):
        """Run deep analysis (decompilation + full YARA)"""
        self.console.print("\n[bold cyan]🔬 Running Deep Analysis (This may take several minutes)...[/bold cyan]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=self.console
        ) as progress:

            task = progress.add_task("[cyan]Starting deep analysis...", total=100)

            try:
                # Standard analysis first
                progress.update(task, advance=15, description="[cyan]Parsing binary structure...")
                metadata, symbols, imports, exports, elf_info = await asyncio.to_thread(
                    analyze_binary_with_lief,
                    str(binary_path)
                )

                self.results['metadata'] = metadata
                self.results['symbols'] = symbols
                self.results['imports'] = imports
                self.results['exports'] = exports

                # Ghidra decompilation
                progress.update(task, advance=20, description="[yellow]Running Ghidra decompilation (slow)...")
                try:
                    ghidra_result = await asyncio.to_thread(
                        analyze_binary_with_ghidra,
                        str(binary_path),
                        timeout=300
                    )
                    self.results['ghidra'] = ghidra_result
                    progress.update(task, advance=40)
                except Exception as e:
                    self.console.print(f"[yellow]⚠️  Ghidra analysis skipped: {str(e)}[/yellow]")
                    progress.update(task, advance=40)

                # YARA scan
                progress.update(task, advance=15, description="[cyan]Running comprehensive YARA scan...")
                yara_results = await asyncio.to_thread(
                    scan_with_yara_rules,
                    str(binary_path)
                )
                self.results['yara'] = yara_results

                progress.update(task, advance=10, description="[green]Deep analysis complete!")

            except Exception as e:
                progress.update(task, description=f"[red]Error: {str(e)}")
                return

        self.display_deep_results()

    def display_metadata_results(self):
        """Display metadata results"""
        self.console.print("\n" + "="*70 + "\n")
        self.console.print("[bold green]📊 Analysis Results - Quick View[/bold green]\n")

        if 'metadata' not in self.results:
            self.console.print("[red]No metadata available[/red]")
            return

        metadata = self.results['metadata']

        # Basic info table
        table = Table(title="Binary Metadata", box=box.ROUNDED, border_style="cyan")
        table.add_column("Property", style="cyan bold", width=25)
        table.add_column("Value", style="white")

        table.add_row("File Type", str(metadata.get('file_type', 'Unknown')))
        table.add_row("Architecture", str(metadata.get('architecture', 'Unknown')))
        table.add_row("File Size", f"{metadata.get('file_size', 0):,} bytes")
        table.add_row("Entry Point", f"0x{metadata.get('entry_point', 0):x}" if metadata.get('entry_point') else "N/A")
        table.add_row("Is Packed", "✅ Yes" if metadata.get('is_packed') else "❌ No")

        self.console.print(table)
        self.console.print()

    def display_standard_results(self):
        """Display standard analysis results"""
        self.console.print("\n" + "="*70 + "\n")
        self.console.print("[bold green]📊 Analysis Results - Standard View[/bold green]\n")

        self.display_metadata_results()

        # Imports table
        if 'imports' in self.results and self.results['imports']:
            imports_table = Table(title="Imported Functions (Top 20)", box=box.ROUNDED, border_style="yellow")
            imports_table.add_column("Library", style="yellow")
            imports_table.add_column("Function", style="white")

            for imp in self.results['imports'][:20]:
                imports_table.add_row(imp.get('library', 'Unknown'), imp.get('name', 'Unknown'))

            self.console.print(imports_table)
            self.console.print(f"[dim]... and {len(self.results['imports']) - 20} more[/dim]\n" if len(self.results['imports']) > 20 else "")

        # YARA results
        if 'yara' in self.results and self.results['yara']:
            yara_table = Table(title="🔍 YARA Scan Results", box=box.ROUNDED, border_style="red")
            yara_table.add_column("Rule", style="red bold")
            yara_table.add_column("Description", style="white")
            yara_table.add_column("Severity", style="yellow")

            for match in self.results['yara']:
                severity = match.get('meta', {}).get('severity', 'unknown')
                desc = match.get('meta', {}).get('description', 'No description')
                yara_table.add_row(match.get('rule', 'Unknown'), desc, severity.upper())

            self.console.print(yara_table)
            self.console.print()
        else:
            self.console.print("[green]✅ No YARA rule matches (binary appears clean)[/green]\n")

    def display_deep_results(self):
        """Display deep analysis results"""
        self.display_standard_results()

        # Ghidra decompilation summary
        if 'ghidra' in self.results and self.results['ghidra']:
            ghidra_info = self.results['ghidra']

            decouple_table = Table(title="🔬 Ghidra Decompilation Results", box=box.ROUNDED, border_style="magenta")
            decouple_table.add_column("Metric", style="magenta bold")
            decouple_table.add_column("Count", style="white", justify="right")

            decouple_table.add_row("Functions Analyzed", str(len(ghidra_info.get('functions', []))))
            decouple_table.add_row("Decompiled Functions", str(len([f for f in ghidra_info.get('functions', []) if f.get('decompiled')])))
            decouple_table.add_row("Strings Found", str(len(ghidra_info.get('strings', []))))

            self.console.print(decouple_table)
            self.console.print()

    def export_results_menu(self):
        """Export results to file"""
        if not self.results:
            self.console.print("[red]No analysis results to export[/red]")
            return

        self.console.print("\n[bold cyan]📤 Export Results[/bold cyan]\n")

        export_format = Prompt.ask(
            "Select export format",
            choices=["json", "txt", "md", "html"],
            default="json"
        )

        output_file = Prompt.ask(
            "Output file name",
            default=f"analysis_results.{export_format}"
        )

        try:
            if export_format == "json":
                import json
                with open(output_file, 'w') as f:
                    json.dump(self.results, f, indent=2, default=str)
            elif export_format == "txt":
                with open(output_file, 'w') as f:
                    f.write("Binary Analysis Results\n")
                    f.write("="*70 + "\n\n")
                    f.write(str(self.results))
            elif export_format == "md":
                with open(output_file, 'w') as f:
                    f.write("# Binary Analysis Results\n\n")
                    f.write("## Metadata\n\n")
                    f.write(f"```json\n{self.results.get('metadata', {})}\n```\n")

            self.console.print(f"[green]✅ Results exported to: {output_file}[/green]")
        except Exception as e:
            self.console.print(f"[red]❌ Export failed: {str(e)}[/red]")

    async def run(self):
        """Main TUI loop"""
        self.show_banner()

        while True:
            choice = self.show_main_menu()

            if choice == 'q':
                self.console.print("\n[bold cyan]👋 Thank you for using VRAgent Binary Analyzer![/bold cyan]\n")
                break

            elif choice in ['1', '2', '3']:
                binary_path = self.select_binary_file()
                if not binary_path:
                    continue

                if choice == '1':
                    await self.run_quick_analysis(binary_path)
                elif choice == '2':
                    await self.run_standard_analysis(binary_path)
                elif choice == '3':
                    await self.run_deep_analysis(binary_path)

                self.console.print("\n[dim]Press Enter to continue...[/dim]")
                input()

            elif choice == '4':
                self.console.print("[yellow]⚠️  View previous results - Not yet implemented[/yellow]")
                input("\nPress Enter to continue...")

            elif choice == '5':
                self.export_results_menu()
                input("\nPress Enter to continue...")

            elif choice == '6':
                self.console.print("[yellow]⚠️  Settings - Not yet implemented[/yellow]")
                input("\nPress Enter to continue...")


def main():
    """Entry point"""
    try:
        tui = BinaryAnalyzerTUI()
        asyncio.run(tui.run())
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
