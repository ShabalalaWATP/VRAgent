#!/usr/bin/env python3
"""
Binary Analyzer - Enhanced Terminal User Interface (TUI)
Interactive terminal-based GUI with streaming analysis, metrics, and cache monitoring
"""

import asyncio
import os
import sys
import json
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime
import time

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import (
        Progress, SpinnerColumn, TextColumn, BarColumn,
        TimeRemainingColumn, TimeElapsedColumn, DownloadColumn
    )
    from rich.prompt import Prompt, Confirm
    from rich.layout import Layout
    from rich.live import Live
    from rich.text import Text
    from rich.tree import Tree
    from rich.markdown import Markdown
    from rich.columns import Columns
    from rich.align import Align
    from rich import box
    from rich.syntax import Syntax
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

# Import streaming analysis if available
try:
    from backend.core.streaming_analysis import streaming_analyzer
    STREAMING_AVAILABLE = True
except ImportError:
    STREAMING_AVAILABLE = False

# Import cache monitoring if available
try:
    from backend.core.cache_enhanced import enhanced_cache
    CACHE_AVAILABLE = True
except ImportError:
    CACHE_AVAILABLE = False


class BinaryAnalyzerTUI:
    """Enhanced Interactive Terminal User Interface for binary analysis"""

    def __init__(self):
        self.console = Console()
        self.results: Dict[str, Any] = {}
        self.settings = {
            'show_detailed_progress': True,
            'enable_streaming': STREAMING_AVAILABLE,
            'show_cache_stats': CACHE_AVAILABLE,
            'color_scheme': 'cyan',
        }
        self.history: list[Dict] = []

    def show_banner(self):
        """Display enhanced welcome banner"""
        banner = Panel(
            Align.center(
                "[bold cyan]VRAgent Binary Analyzer[/bold cyan]\n"
                "[dim]Enhanced Terminal User Interface[/dim]\n\n"
                f"[green]✓ Streaming Analysis: {'Enabled' if STREAMING_AVAILABLE else 'Disabled'}[/green]\n"
                f"[green]✓ Cache Monitoring: {'Enabled' if CACHE_AVAILABLE else 'Disabled'}[/green]\n"
                f"[green]✓ Real-time Progress: Enabled[/green]"
            ),
            box=box.DOUBLE,
            border_style="bold cyan",
            padding=(1, 2)
        )
        self.console.print(banner)
        self.console.print()

    def show_main_menu(self) -> str:
        """Display enhanced main menu"""
        menu = Table(show_header=False, box=box.ROUNDED, border_style="cyan", padding=(0, 2))
        menu.add_column("Option", style="bold yellow", width=10)
        menu.add_column("Description", style="white", width=50)
        menu.add_column("Details", style="dim", width=30)

        menu.add_row(
            "1",
            "Quick Analysis",
            "Fast, basic metadata only"
        )
        menu.add_row(
            "2",
            "Standard Analysis",
            "Recommended for most cases"
        )
        menu.add_row(
            "3",
            "Deep Analysis",
            "Full decompilation + YARA"
        )

        if STREAMING_AVAILABLE:
            menu.add_row(
                "4",
                "Streaming Analysis",
                "For files >500MB (memory-efficient)"
            )

        menu.add_row("", "", "")  # Separator

        menu.add_row(
            "h",
            "View History",
            f"{len(self.history)} analysis in history"
        )
        menu.add_row(
            "c",
            "Cache Statistics",
            "View cache performance" if CACHE_AVAILABLE else "[dim]Not available[/dim]"
        )
        menu.add_row(
            "e",
            "Export Results",
            "Save to file (JSON/TXT/MD)"
        )
        menu.add_row(
            "s",
            "Settings",
            "Configure analyzer"
        )
        menu.add_row(
            "q",
            "Quit",
            "Exit analyzer"
        )

        self.console.print(Panel(menu, title="[bold cyan]Main Menu[/bold cyan]", border_style="cyan"))
        self.console.print()

        choices = ["1", "2", "3", "h", "c", "e", "s", "q"]
        if STREAMING_AVAILABLE:
            choices.insert(3, "4")

        choice = Prompt.ask(
            "[bold cyan]Select option[/bold cyan]",
            choices=choices,
            default="2"
        )
        return choice

    def select_binary_file(self) -> Optional[Path]:
        """Enhanced file selection with detailed info"""
        self.console.print("\n[bold cyan]📂 Select Binary File[/bold cyan]\n")

        while True:
            file_path = Prompt.ask(
                "Enter the path to the binary file",
                default="example.exe"
            )

            path = Path(file_path)
            if path.exists() and path.is_file():
                # Show detailed file info
                stat = path.stat()
                size_bytes = stat.st_size
                size_mb = size_bytes / (1024 * 1024)
                size_gb = size_bytes / (1024 * 1024 * 1024)

                info_table = Table(show_header=False, box=box.SIMPLE, border_style="green")
                info_table.add_column("Property", style="cyan bold")
                info_table.add_column("Value", style="white")

                info_table.add_row("📄 File Name", path.name)
                info_table.add_row("📁 Directory", str(path.parent))
                info_table.add_row("📏 Size", f"{size_bytes:,} bytes ({size_mb:.2f} MB)")

                if size_gb > 0.5:
                    info_table.add_row(
                        "⚠️  Large File",
                        f"{size_gb:.2f} GB - Consider streaming analysis" if STREAMING_AVAILABLE else f"{size_gb:.2f} GB"
                    )

                info_table.add_row("🕒 Modified", datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"))
                info_table.add_row("🔐 Permissions", oct(stat.st_mode)[-3:])

                self.console.print(Panel(info_table, title="File Information", border_style="green"))

                if Confirm.ask("Proceed with this file?", default=True):
                    return path
            else:
                self.console.print(f"[bold red]❌ File not found: {file_path}[/bold red]")
                if not Confirm.ask("Try again?", default=True):
                    return None

    async def run_quick_analysis(self, binary_path: Path):
        """Enhanced quick analysis with detailed progress"""
        self.console.print("\n[bold cyan]⚡ Running Quick Analysis...[/bold cyan]\n")

        start_time = time.time()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(complete_style="cyan", finished_style="green"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=self.console,
            expand=True
        ) as progress:

            task = progress.add_task("[cyan]Initializing...", total=100)

            # Step 1: Validation
            progress.update(task, advance=10, description="[cyan]Validating file...")
            await asyncio.sleep(0.1)

            # Step 2: Parse headers
            progress.update(task, advance=20, description="[cyan]Parsing PE/ELF headers...")
            try:
                metadata, _, _, _, _ = await asyncio.to_thread(
                    analyze_binary_with_lief,
                    str(binary_path)
                )
                progress.update(task, advance=40, description="[cyan]Extracting metadata...")

                self.results['metadata'] = metadata
                self.results['analysis_type'] = 'quick'
                self.results['file_path'] = str(binary_path)
                self.results['timestamp'] = datetime.now().isoformat()

                progress.update(task, advance=30, description="[green]✓ Analysis complete!")

            except Exception as e:
                progress.update(task, description=f"[red]✗ Error: {str(e)}")
                self.console.print(f"\n[red]Analysis failed: {str(e)}[/red]")
                return

        duration = time.time() - start_time
        self.results['duration_seconds'] = duration

        # Add to history
        self.history.append({
            'timestamp': self.results['timestamp'],
            'file': binary_path.name,
            'type': 'quick',
            'duration': duration
        })

        self.display_metadata_results()
        self.console.print(f"\n[dim]Analysis completed in {duration:.2f} seconds[/dim]")

    async def run_standard_analysis(self, binary_path: Path):
        """Enhanced standard analysis"""
        self.console.print("\n[bold cyan]🔍 Running Standard Analysis...[/bold cyan]\n")

        start_time = time.time()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(complete_style="cyan", finished_style="green"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=self.console,
            expand=True
        ) as progress:

            main_task = progress.add_task("[cyan]Starting analysis...", total=100)

            try:
                # LIEF analysis
                progress.update(main_task, advance=15, description="[cyan]Parsing binary structure...")
                metadata, symbols, imports, exports, elf_info = await asyncio.to_thread(
                    analyze_binary_with_lief,
                    str(binary_path)
                )

                self.results['metadata'] = metadata
                self.results['symbols'] = symbols
                self.results['imports'] = imports
                self.results['exports'] = exports
                self.results['analysis_type'] = 'standard'
                self.results['file_path'] = str(binary_path)
                self.results['timestamp'] = datetime.now().isoformat()

                progress.update(main_task, advance=35, description="[cyan]Analyzing imports/exports...")

                # YARA scan
                progress.update(main_task, advance=20, description="[yellow]Running YARA scan...")
                yara_results = await asyncio.to_thread(
                    scan_with_yara_rules,
                    str(binary_path)
                )
                self.results['yara'] = yara_results

                progress.update(main_task, advance=30, description="[green]✓ Analysis complete!")

            except Exception as e:
                progress.update(main_task, description=f"[red]✗ Error: {str(e)}")
                self.console.print(f"\n[red]Analysis failed: {str(e)}[/red]")
                return

        duration = time.time() - start_time
        self.results['duration_seconds'] = duration

        # Add to history
        self.history.append({
            'timestamp': self.results['timestamp'],
            'file': binary_path.name,
            'type': 'standard',
            'duration': duration
        })

        self.display_standard_results()
        self.console.print(f"\n[dim]Analysis completed in {duration:.2f} seconds[/dim]")

    async def run_deep_analysis(self, binary_path: Path):
        """Enhanced deep analysis"""
        self.console.print("\n[bold cyan]🔬 Running Deep Analysis (This may take several minutes)...[/bold cyan]\n")

        start_time = time.time()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(complete_style="cyan", finished_style="green"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=self.console,
            expand=True
        ) as progress:

            main_task = progress.add_task("[cyan]Starting deep analysis...", total=100)

            try:
                # Standard analysis first
                progress.update(main_task, advance=10, description="[cyan]Parsing binary structure...")
                metadata, symbols, imports, exports, elf_info = await asyncio.to_thread(
                    analyze_binary_with_lief,
                    str(binary_path)
                )

                self.results['metadata'] = metadata
                self.results['symbols'] = symbols
                self.results['imports'] = imports
                self.results['exports'] = exports
                self.results['analysis_type'] = 'deep'
                self.results['file_path'] = str(binary_path)
                self.results['timestamp'] = datetime.now().isoformat()

                progress.update(main_task, advance=15)

                # Ghidra decompilation
                progress.update(main_task, advance=10, description="[magenta]Launching Ghidra (this is slow)...")
                try:
                    ghidra_result = await asyncio.to_thread(
                        analyze_binary_with_ghidra,
                        str(binary_path),
                        timeout=300
                    )
                    self.results['ghidra'] = ghidra_result
                    progress.update(main_task, advance=40, description="[magenta]Decompilation complete...")
                except Exception as e:
                    self.console.print(f"[yellow]⚠️  Ghidra analysis skipped: {str(e)}[/yellow]")
                    progress.update(main_task, advance=40)

                # YARA scan
                progress.update(main_task, advance=10, description="[yellow]Running comprehensive YARA scan...")
                yara_results = await asyncio.to_thread(
                    scan_with_yara_rules,
                    str(binary_path)
                )
                self.results['yara'] = yara_results

                progress.update(main_task, advance=15, description="[green]✓ Deep analysis complete!")

            except Exception as e:
                progress.update(main_task, description=f"[red]✗ Error: {str(e)}")
                self.console.print(f"\n[red]Analysis failed: {str(e)}[/red]")
                return

        duration = time.time() - start_time
        self.results['duration_seconds'] = duration

        # Add to history
        self.history.append({
            'timestamp': self.results['timestamp'],
            'file': binary_path.name,
            'type': 'deep',
            'duration': duration
        })

        self.display_deep_results()
        self.console.print(f"\n[dim]Analysis completed in {duration:.2f} seconds[/dim]")

    async def run_streaming_analysis(self, binary_path: Path):
        """Streaming analysis for large files"""
        if not STREAMING_AVAILABLE:
            self.console.print("[red]Streaming analysis not available[/red]")
            return

        self.console.print("\n[bold cyan]📊 Running Streaming Analysis (Memory-Efficient)...[/bold cyan]\n")

        start_time = time.time()
        file_size = binary_path.stat().st_size

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(complete_style="cyan", finished_style="green"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            DownloadColumn(),
            TimeElapsedColumn(),
            console=self.console,
            expand=True
        ) as progress:

            def progress_callback(bytes_processed, total_bytes):
                """Update progress bar"""
                percentage = (bytes_processed / total_bytes) * 100
                progress.update(stream_task, completed=bytes_processed)

            stream_task = progress.add_task(
                "[cyan]Streaming analysis...",
                total=file_size
            )

            try:
                result = await streaming_analyzer.analyze_large_binary_streaming(
                    str(binary_path),
                    analysis_type="standard",
                    progress_callback=progress_callback
                )

                self.results = result
                self.results['analysis_type'] = 'streaming'
                self.results['timestamp'] = datetime.now().isoformat()

                progress.update(stream_task, description="[green]✓ Streaming analysis complete!")

            except Exception as e:
                progress.update(stream_task, description=f"[red]✗ Error: {str(e)}")
                self.console.print(f"\n[red]Analysis failed: {str(e)}[/red]")
                return

        duration = time.time() - start_time
        self.results['duration_seconds'] = duration

        # Add to history
        self.history.append({
            'timestamp': self.results['timestamp'],
            'file': binary_path.name,
            'type': 'streaming',
            'duration': duration
        })

        self.display_streaming_results()
        self.console.print(f"\n[dim]Analysis completed in {duration:.2f} seconds[/dim]")

    def display_metadata_results(self):
        """Enhanced metadata display"""
        self.console.print("\n" + "=" * 80 + "\n")
        self.console.print("[bold green]📊 Analysis Results - Quick View[/bold green]\n")

        if 'metadata' not in self.results:
            self.console.print("[red]No metadata available[/red]")
            return

        metadata = self.results['metadata']

        # Create two-column layout
        table = Table(title="Binary Metadata", box=box.ROUNDED, border_style="cyan", show_header=False)
        table.add_column("Property", style="cyan bold", width=30)
        table.add_column("Value", style="white", width=45)

        table.add_row("📄 File Type", str(metadata.get('file_type', 'Unknown')))
        table.add_row("🏗️  Architecture", str(metadata.get('architecture', 'Unknown')))
        table.add_row("📏 File Size", f"{metadata.get('file_size', 0):,} bytes")

        entry_point = metadata.get('entry_point')
        table.add_row("🎯 Entry Point", f"0x{entry_point:x}" if entry_point else "N/A")

        is_packed = metadata.get('is_packed')
        packed_str = "[red]✅ Yes (Possibly malicious)[/red]" if is_packed else "[green]❌ No[/green]"
        table.add_row("📦 Is Packed", packed_str)

        self.console.print(table)
        self.console.print()

    def display_standard_results(self):
        """Enhanced standard results display"""
        self.console.print("\n" + "=" * 80 + "\n")
        self.console.print("[bold green]📊 Analysis Results - Standard View[/bold green]\n")

        self.display_metadata_results()

        # Statistics panel
        stats_table = Table(title="Analysis Statistics", box=box.SIMPLE, border_style="blue", show_header=False)
        stats_table.add_column("Metric", style="blue bold")
        stats_table.add_column("Count", style="white", justify="right")

        if 'imports' in self.results:
            stats_table.add_row("📥 Imported Functions", str(len(self.results['imports'])))
        if 'exports' in self.results:
            stats_table.add_row("📤 Exported Functions", str(len(self.results['exports'])))
        if 'symbols' in self.results:
            stats_table.add_row("🔤 Symbols", str(len(self.results['symbols'])))

        self.console.print(stats_table)
        self.console.print()

        # Imports table (top 20)
        if 'imports' in self.results and self.results['imports']:
            imports_table = Table(
                title="Imported Functions (Top 20)",
                box=box.ROUNDED,
                border_style="yellow",
                show_header=True
            )
            imports_table.add_column("Library", style="yellow bold", width=25)
            imports_table.add_column("Function", style="white", width=40)

            for imp in self.results['imports'][:20]:
                imports_table.add_row(
                    imp.get('library', 'Unknown')[:25],
                    imp.get('name', 'Unknown')[:40]
                )

            self.console.print(imports_table)
            if len(self.results['imports']) > 20:
                self.console.print(f"[dim]... and {len(self.results['imports']) - 20} more[/dim]\n")

        # YARA results
        if 'yara' in self.results:
            if self.results['yara']:
                yara_table = Table(
                    title="🔍 YARA Scan Results",
                    box=box.HEAVY,
                    border_style="red",
                    show_header=True
                )
                yara_table.add_column("Rule", style="red bold", width=25)
                yara_table.add_column("Description", style="white", width=40)
                yara_table.add_column("Severity", style="yellow bold", justify="center", width=10)

                for match in self.results['yara']:
                    severity = match.get('meta', {}).get('severity', 'unknown')
                    desc = match.get('meta', {}).get('description', 'No description')

                    # Color code severity
                    if severity.lower() in ['critical', 'high']:
                        severity_display = f"[red bold]{severity.upper()}[/red bold]"
                    elif severity.lower() == 'medium':
                        severity_display = f"[yellow]{severity.upper()}[/yellow]"
                    else:
                        severity_display = f"[blue]{severity.upper()}[/blue]"

                    yara_table.add_row(match.get('rule', 'Unknown'), desc[:40], severity_display)

                self.console.print(yara_table)
                self.console.print()
            else:
                self.console.print(Panel(
                    "[green]✅ No YARA rule matches found\nBinary appears clean based on signature analysis[/green]",
                    title="YARA Scan Results",
                    border_style="green"
                ))
                self.console.print()

    def display_deep_results(self):
        """Enhanced deep results display"""
        self.display_standard_results()

        # Ghidra decompilation summary
        if 'ghidra' in self.results and self.results['ghidra']:
            ghidra_info = self.results['ghidra']

            ghidra_table = Table(
                title="🔬 Ghidra Decompilation Results",
                box=box.ROUNDED,
                border_style="magenta",
                show_header=False
            )
            ghidra_table.add_column("Metric", style="magenta bold", width=35)
            ghidra_table.add_column("Count", style="white", justify="right", width=15)

            functions = ghidra_info.get('functions', [])
            decompiled = [f for f in functions if f.get('decompiled')]

            ghidra_table.add_row("Total Functions Analyzed", str(len(functions)))
            ghidra_table.add_row("Successfully Decompiled", str(len(decompiled)))
            ghidra_table.add_row("Strings Found", str(len(ghidra_info.get('strings', []))))

            self.console.print(ghidra_table)
            self.console.print()

    def display_streaming_results(self):
        """Display streaming analysis results"""
        self.console.print("\n" + "=" * 80 + "\n")
        self.console.print("[bold green]📊 Streaming Analysis Results[/bold green]\n")

        if 'status' in self.results and self.results['status'] != 'completed':
            self.console.print(f"[red]Analysis status: {self.results.get('status', 'unknown')}[/red]")
            return

        # File info
        if 'file_info' in self.results:
            info = self.results['file_info']
            info_table = Table(box=box.ROUNDED, border_style="cyan", show_header=False)
            info_table.add_column("Property", style="cyan bold", width=25)
            info_table.add_column("Value", style="white", width=50)

            info_table.add_row("Size", f"{info['size_bytes']:,} bytes ({info['size_gb']:.2f} GB)")
            info_table.add_row("SHA256", info['sha256'][:64])
            info_table.add_row("File Type", info.get('file_type', 'Unknown'))
            info_table.add_row("Format", self.results.get('format', 'Unknown'))
            info_table.add_row("Architecture", self.results.get('architecture', 'Unknown'))

            self.console.print(info_table)
            self.console.print()

        # Hashes
        if 'hashes' in self.results:
            hash_table = Table(title="File Hashes", box=box.SIMPLE, border_style="green", show_header=False)
            hash_table.add_column("Algorithm", style="green bold", width=15)
            hash_table.add_column("Hash", style="white", width=64)

            for algo, hash_val in self.results['hashes'].items():
                hash_table.add_row(algo.upper(), hash_val)

            self.console.print(hash_table)
            self.console.print()

        # Strings
        if 'strings_count' in self.results:
            self.console.print(f"[cyan]Strings Found: {self.results['strings_count']}[/cyan]")
            if 'strings_sample' in self.results:
                self.console.print("[dim]Sample (first 10):[/dim]")
                for s in self.results['strings_sample'][:10]:
                    self.console.print(f"  [dim]{s[:80]}[/dim]")
            self.console.print()

        # Entropy analysis
        if 'high_entropy_blocks' in self.results and self.results['high_entropy_blocks']:
            entropy_table = Table(
                title="⚠️  High Entropy Blocks (Possible Encryption/Packing)",
                box=box.ROUNDED,
                border_style="yellow"
            )
            entropy_table.add_column("Offset", style="yellow bold")
            entropy_table.add_column("Entropy", style="white", justify="right")

            for block in self.results['high_entropy_blocks'][:20]:
                entropy_table.add_row(block['offset'], f"{block['entropy']:.2f}")

            self.console.print(entropy_table)
            self.console.print()

    def show_history(self):
        """Display analysis history"""
        if not self.history:
            self.console.print("[yellow]No analysis history available[/yellow]")
            return

        self.console.print("\n[bold cyan]📜 Analysis History[/bold cyan]\n")

        history_table = Table(box=box.ROUNDED, border_style="cyan")
        history_table.add_column("#", style="cyan bold", width=5, justify="right")
        history_table.add_column("Timestamp", style="white", width=20)
        history_table.add_column("File", style="yellow", width=35)
        history_table.add_column("Type", style="green", width=15)
        history_table.add_column("Duration", style="blue", justify="right", width=12)

        for idx, entry in enumerate(self.history, 1):
            timestamp = datetime.fromisoformat(entry['timestamp']).strftime("%Y-%m-%d %H:%M:%S")
            history_table.add_row(
                str(idx),
                timestamp,
                entry['file'],
                entry['type'].capitalize(),
                f"{entry['duration']:.2f}s"
            )

        self.console.print(history_table)
        self.console.print()

    async def show_cache_stats(self):
        """Display cache statistics"""
        if not CACHE_AVAILABLE:
            self.console.print("[yellow]Cache monitoring not available[/yellow]")
            return

        self.console.print("\n[bold cyan]📊 Cache Statistics[/bold cyan]\n")

        try:
            stats = await enhanced_cache.get_stats()

            # Cache performance
            perf_table = Table(title="Cache Performance", box=box.ROUNDED, border_style="green", show_header=False)
            perf_table.add_column("Metric", style="green bold", width=25)
            perf_table.add_column("Value", style="white", justify="right", width=20)

            hit_rate = stats.get('hit_rate_percent', 0)
            hit_rate_color = "green" if hit_rate > 70 else "yellow" if hit_rate > 50 else "red"

            perf_table.add_row("Hit Rate", f"[{hit_rate_color}]{hit_rate:.2f}%[/{hit_rate_color}]")
            perf_table.add_row("Total Hits", f"{stats.get('hits', 0):,}")
            perf_table.add_row("Total Misses", f"{stats.get('misses', 0):,}")
            perf_table.add_row("Set Operations", f"{stats.get('sets', 0):,}")
            perf_table.add_row("Delete Operations", f"{stats.get('deletes', 0):,}")
            perf_table.add_row("Errors", f"{stats.get('errors', 0):,}")

            self.console.print(perf_table)
            self.console.print()

        except Exception as e:
            self.console.print(f"[red]Error fetching cache stats: {str(e)}[/red]")

    def show_settings(self):
        """Display and modify settings"""
        self.console.print("\n[bold cyan]⚙️  Settings[/bold cyan]\n")

        settings_table = Table(box=box.ROUNDED, border_style="cyan")
        settings_table.add_column("Setting", style="cyan bold", width=30)
        settings_table.add_column("Value", style="white", width=20)
        settings_table.add_column("Description", style="dim", width=40)

        settings_table.add_row(
            "show_detailed_progress",
            "✓ Enabled" if self.settings['show_detailed_progress'] else "✗ Disabled",
            "Show detailed progress during analysis"
        )
        settings_table.add_row(
            "enable_streaming",
            "✓ Enabled" if self.settings['enable_streaming'] else "✗ Disabled",
            "Enable streaming for large files"
        )
        settings_table.add_row(
            "show_cache_stats",
            "✓ Enabled" if self.settings['show_cache_stats'] else "✗ Disabled",
            "Display cache statistics"
        )
        settings_table.add_row(
            "color_scheme",
            self.settings['color_scheme'],
            "UI color scheme (cyan, green, blue)"
        )

        self.console.print(settings_table)
        self.console.print("\n[dim]Settings modification coming in next update[/dim]\n")

    def export_results_menu(self):
        """Enhanced export menu"""
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
            default=f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{export_format}"
        )

        try:
            if export_format == "json":
                with open(output_file, 'w') as f:
                    json.dump(self.results, f, indent=2, default=str)
            elif export_format == "txt":
                with open(output_file, 'w') as f:
                    f.write("=" * 80 + "\n")
                    f.write("VRAgent Binary Analysis Results\n")
                    f.write("=" * 80 + "\n\n")
                    f.write(json.dumps(self.results, indent=2, default=str))
            elif export_format == "md":
                with open(output_file, 'w') as f:
                    f.write("# Binary Analysis Results\n\n")
                    f.write(f"**File:** {self.results.get('file_path', 'Unknown')}\n\n")
                    f.write(f"**Analysis Type:** {self.results.get('analysis_type', 'Unknown')}\n\n")
                    f.write(f"**Timestamp:** {self.results.get('timestamp', 'Unknown')}\n\n")
                    f.write("## Metadata\n\n")
                    f.write(f"```json\n{json.dumps(self.results.get('metadata', {}), indent=2)}\n```\n")

            self.console.print(f"[green]✅ Results exported to: {output_file}[/green]")
        except Exception as e:
            self.console.print(f"[red]❌ Export failed: {str(e)}[/red]")

    async def run(self):
        """Enhanced main TUI loop"""
        self.show_banner()

        while True:
            choice = self.show_main_menu()

            if choice == 'q':
                self.console.print("\n[bold cyan]👋 Thank you for using VRAgent Binary Analyzer![/bold cyan]\n")
                break

            elif choice in ['1', '2', '3', '4']:
                binary_path = self.select_binary_file()
                if not binary_path:
                    continue

                if choice == '1':
                    await self.run_quick_analysis(binary_path)
                elif choice == '2':
                    await self.run_standard_analysis(binary_path)
                elif choice == '3':
                    await self.run_deep_analysis(binary_path)
                elif choice == '4' and STREAMING_AVAILABLE:
                    await self.run_streaming_analysis(binary_path)

                self.console.print("\n[dim]Press Enter to continue...[/dim]")
                input()

            elif choice == 'h':
                self.show_history()
                input("\nPress Enter to continue...")

            elif choice == 'c':
                await self.show_cache_stats()
                input("\nPress Enter to continue...")

            elif choice == 'e':
                self.export_results_menu()
                input("\nPress Enter to continue...")

            elif choice == 's':
                self.show_settings()
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
