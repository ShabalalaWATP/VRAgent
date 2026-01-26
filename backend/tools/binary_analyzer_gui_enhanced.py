#!/usr/bin/env python3
"""
Binary Analyzer - Enhanced Desktop GUI Application
Modern desktop application with drag-and-drop, streaming analysis, and real-time metrics
"""

import asyncio
import json
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from tkinter.dnd import *
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime
import time

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from backend.services.reverse_engineering_service import (
        analyze_binary_with_lief,
        analyze_binary_with_ghidra,
        scan_with_yara_rules,
    )
except ImportError as e:
    print(f"ERROR: Could not import backend services: {e}")
    print("Make sure you're running from the project root")
    sys.exit(1)

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


class EnhancedBinaryAnalyzerGUI:
    """Enhanced Desktop GUI for binary analysis"""

    def __init__(self, root):
        self.root = root
        self.root.title("VRAgent Binary Analyzer - Enhanced GUI")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)

        # Configure modern style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_modern_style()

        # Variables
        self.binary_path = tk.StringVar()
        self.analysis_mode = tk.StringVar(value="standard")
        self.results: Dict[str, Any] = {}
        self.is_analyzing = False
        self.progress_value = tk.IntVar(value=0)
        self.progress_text = tk.StringVar(value="Ready")
        self.analysis_start_time = 0

        self.setup_ui()

        # Enable drag and drop
        self.setup_drag_drop()

    def configure_modern_style(self):
        """Configure modern UI styling"""
        # Colors
        bg_color = "#f0f0f0"
        accent_color = "#0066cc"
        success_color = "#28a745"
        warning_color = "#ffc107"
        danger_color = "#dc3545"

        # Configure styles
        self.style.configure('Accent.TButton', font=('Arial', 10, 'bold'), foreground=accent_color)
        self.style.configure('Success.TLabel', foreground=success_color)
        self.style.configure('Warning.TLabel', foreground=warning_color)
        self.style.configure('Danger.TLabel', foreground=danger_color)

    def setup_ui(self):
        """Setup enhanced user interface"""
        # Main container with padding
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=3)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)

        # Header
        self.create_header(main_frame)

        # File selection section
        self.create_file_section(main_frame)

        # Results section (main area)
        self.create_results_section(main_frame)

        # Sidebar (metrics & cache)
        self.create_sidebar(main_frame)

        # Status bar
        self.create_status_bar(main_frame)

    def create_header(self, parent):
        """Create enhanced header"""
        header_frame = ttk.Frame(parent)
        header_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 20))

        title_label = ttk.Label(
            header_frame,
            text="🔬 VRAgent Binary Analyzer",
            font=("Arial", 20, "bold"),
            foreground="#0066cc"
        )
        title_label.grid(row=0, column=0, sticky=tk.W)

        subtitle_label = ttk.Label(
            header_frame,
            text="Enhanced GUI with Streaming Analysis & Real-time Metrics",
            font=("Arial", 10),
            foreground="#666666"
        )
        subtitle_label.grid(row=1, column=0, sticky=tk.W)

        # Feature indicators
        features_frame = ttk.Frame(header_frame)
        features_frame.grid(row=0, column=1, rowspan=2, sticky=tk.E)

        if STREAMING_AVAILABLE:
            ttk.Label(
                features_frame,
                text="✓ Streaming",
                foreground="#28a745",
                font=("Arial", 8)
            ).pack(side=tk.LEFT, padx=5)

        if CACHE_AVAILABLE:
            ttk.Label(
                features_frame,
                text="✓ Cache",
                foreground="#28a745",
                font=("Arial", 8)
            ).pack(side=tk.LEFT, padx=5)

    def create_file_section(self, parent):
        """Create enhanced file selection section"""
        file_frame = ttk.LabelFrame(parent, text="Binary Selection & Analysis Options", padding="15")
        file_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        file_frame.columnconfigure(1, weight=1)

        # File path with drag-drop hint
        ttk.Label(file_frame, text="Binary File:", font=("Arial", 9, "bold")).grid(
            row=0, column=0, sticky=tk.W, padx=(0, 10)
        )

        file_entry_frame = ttk.Frame(file_frame)
        file_entry_frame.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        file_entry_frame.columnconfigure(0, weight=1)

        file_entry = ttk.Entry(file_entry_frame, textvariable=self.binary_path, font=("Arial", 10))
        file_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))

        ttk.Label(
            file_entry_frame,
            text="(or drag & drop file here)",
            font=("Arial", 8),
            foreground="#999999"
        ).grid(row=1, column=0, sticky=tk.W)

        browse_btn = ttk.Button(file_entry_frame, text="Browse...", command=self.browse_file)
        browse_btn.grid(row=0, column=1)

        # File info display
        self.file_info_label = ttk.Label(
            file_frame,
            text="",
            foreground="#666666",
            font=("Arial", 8)
        )
        self.file_info_label.grid(row=1, column=1, sticky=tk.W, pady=(5, 10))

        # Analysis mode with descriptions
        ttk.Label(file_frame, text="Analysis Mode:", font=("Arial", 9, "bold")).grid(
            row=2, column=0, sticky=tk.W, padx=(0, 10), pady=(10, 0)
        )

        mode_frame = ttk.Frame(file_frame)
        mode_frame.grid(row=2, column=1, sticky=tk.W, pady=(10, 0))

        modes = [
            ("quick", "Quick", "Fast, basic metadata only"),
            ("standard", "Standard", "Recommended for most cases"),
            ("deep", "Deep", "Full decompilation (slow)"),
        ]

        if STREAMING_AVAILABLE:
            modes.append(("streaming", "Streaming", "For large files >500MB"))

        for idx, (value, label, desc) in enumerate(modes):
            rb_frame = ttk.Frame(mode_frame)
            rb_frame.grid(row=0, column=idx, padx=(0, 20), sticky=tk.W)

            ttk.Radiobutton(
                rb_frame,
                text=label,
                variable=self.analysis_mode,
                value=value
            ).pack(anchor=tk.W)

            ttk.Label(
                rb_frame,
                text=desc,
                font=("Arial", 7),
                foreground="#999999"
            ).pack(anchor=tk.W)

        # Action buttons
        button_frame = ttk.Frame(file_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=(20, 0))

        self.analyze_btn = ttk.Button(
            button_frame,
            text="🔍 Start Analysis",
            command=self.start_analysis,
            style="Accent.TButton"
        )
        self.analyze_btn.pack(side=tk.LEFT, padx=(0, 10))

        ttk.Button(
            button_frame,
            text="📤 Export Results",
            command=self.export_results
        ).pack(side=tk.LEFT, padx=(0, 10))

        ttk.Button(
            button_frame,
            text="🗑️ Clear",
            command=self.clear_results
        ).pack(side=tk.LEFT)

    def create_results_section(self, parent):
        """Create enhanced results section"""
        results_frame = ttk.LabelFrame(parent, text="Analysis Results", padding="15")
        results_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)

        # Notebook for tabbed results
        self.notebook = ttk.Notebook(results_frame)
        self.notebook.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Create tabs with enhanced styling
        self.create_result_tabs()

        # Progress bar with percentage and ETA
        progress_frame = ttk.Frame(results_frame)
        progress_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(15, 0))
        progress_frame.columnconfigure(0, weight=1)

        self.progress = ttk.Progressbar(
            progress_frame,
            mode='determinate',
            variable=self.progress_value,
            maximum=100
        )
        self.progress.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))

        self.progress_label = ttk.Label(
            progress_frame,
            textvariable=self.progress_text,
            font=("Arial", 9),
            foreground="#666666"
        )
        self.progress_label.grid(row=1, column=0, sticky=tk.W)

    def create_result_tabs(self):
        """Create result display tabs"""
        # Summary tab
        self.summary_text = scrolledtext.ScrolledText(
            self.notebook,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg="#f5f5f5",
            relief=tk.FLAT,
            padx=10,
            pady=10
        )
        self.notebook.add(self.summary_text, text="📊 Summary")

        # Metadata tab
        self.metadata_text = scrolledtext.ScrolledText(
            self.notebook,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg="#f5f5f5",
            relief=tk.FLAT,
            padx=10,
            pady=10
        )
        self.notebook.add(self.metadata_text, text="📋 Metadata")

        # Imports tab
        self.imports_text = scrolledtext.ScrolledText(
            self.notebook,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg="#f5f5f5",
            relief=tk.FLAT,
            padx=10,
            pady=10
        )
        self.notebook.add(self.imports_text, text="📥 Imports")

        # YARA tab with syntax highlighting
        self.yara_text = scrolledtext.ScrolledText(
            self.notebook,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg="#f5f5f5",
            relief=tk.FLAT,
            padx=10,
            pady=10
        )
        self.notebook.add(self.yara_text, text="🔍 YARA Matches")

        # Decompilation tab
        self.decomp_text = scrolledtext.ScrolledText(
            self.notebook,
            wrap=tk.WORD,
            font=("Consolas", 8),
            bg="#f5f5f5",
            relief=tk.FLAT,
            padx=10,
            pady=10
        )
        self.notebook.add(self.decomp_text, text="🔬 Decompilation")

    def create_sidebar(self, parent):
        """Create sidebar with metrics and cache stats"""
        sidebar_frame = ttk.Frame(parent)
        sidebar_frame.grid(row=2, column=1, sticky=(tk.N, tk.S, tk.E, tk.W))
        sidebar_frame.rowconfigure(1, weight=1)

        # Cache statistics
        if CACHE_AVAILABLE:
            cache_frame = ttk.LabelFrame(sidebar_frame, text="Cache Statistics", padding="10")
            cache_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N), pady=(0, 10))

            self.cache_hit_rate = tk.StringVar(value="N/A")
            self.cache_operations = tk.StringVar(value="N/A")

            ttk.Label(cache_frame, text="Hit Rate:", font=("Arial", 8, "bold")).pack(anchor=tk.W)
            self.cache_hit_label = ttk.Label(
                cache_frame,
                textvariable=self.cache_hit_rate,
                font=("Arial", 12)
            )
            self.cache_hit_label.pack(anchor=tk.W, pady=(0, 10))

            ttk.Label(cache_frame, text="Operations:", font=("Arial", 8, "bold")).pack(anchor=tk.W)
            ttk.Label(
                cache_frame,
                textvariable=self.cache_operations,
                font=("Arial", 9),
                foreground="#666666"
            ).pack(anchor=tk.W)

            # Refresh button
            ttk.Button(
                cache_frame,
                text="🔄 Refresh",
                command=self.update_cache_stats
            ).pack(pady=(10, 0))

        # Analysis statistics
        stats_frame = ttk.LabelFrame(sidebar_frame, text="Analysis Statistics", padding="10")
        stats_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N), pady=(0, 10))

        self.stats_labels = {}

        stat_items = [
            ("analyses", "Total Analyses"),
            ("duration", "Last Duration"),
            ("file_size", "Last File Size"),
        ]

        for key, label in stat_items:
            ttk.Label(stats_frame, text=f"{label}:", font=("Arial", 8)).pack(anchor=tk.W)
            var = tk.StringVar(value="0")
            self.stats_labels[key] = var
            ttk.Label(
                stats_frame,
                textvariable=var,
                font=("Arial", 9, "bold"),
                foreground="#0066cc"
            ).pack(anchor=tk.W, pady=(0, 10))

    def create_status_bar(self, parent):
        """Create enhanced status bar"""
        status_frame = ttk.Frame(parent, relief=tk.SUNKEN)
        status_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(15, 0))
        status_frame.columnconfigure(0, weight=1)

        self.status_label = ttk.Label(
            status_frame,
            text="Ready",
            anchor=tk.W,
            font=("Arial", 9),
            padding=(5, 2)
        )
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Add timestamp
        self.timestamp_label = ttk.Label(
            status_frame,
            text="",
            anchor=tk.E,
            font=("Arial", 8),
            foreground="#999999",
            padding=(5, 2)
        )
        self.timestamp_label.pack(side=tk.RIGHT)

    def setup_drag_drop(self):
        """Setup drag and drop support"""
        def on_drop(event):
            files = self.root.tk.splitlist(event.data)
            if files:
                file_path = files[0]
                # Remove curly braces if present (Windows)
                if file_path.startswith('{') and file_path.endswith('}'):
                    file_path = file_path[1:-1]
                self.binary_path.set(file_path)
                self.update_file_info()

        # Make the entry widget accept drops
        self.root.drop_target_register(DND_FILES)
        self.root.dnd_bind('<<Drop>>', on_drop)

    def browse_file(self):
        """Open file browser dialog"""
        filename = filedialog.askopenfilename(
            title="Select Binary File",
            filetypes=[
                ("Executable Files", "*.exe;*.dll;*.so;*.elf;*.bin"),
                ("Android APK", "*.apk"),
                ("All Files", "*.*")
            ]
        )
        if filename:
            self.binary_path.set(filename)
            self.update_file_info()

    def update_file_info(self):
        """Update file information display"""
        file_path = self.binary_path.get()
        if not file_path or not Path(file_path).exists():
            self.file_info_label.config(text="")
            return

        path = Path(file_path)
        size = path.stat().st_size
        size_mb = size / (1024 * 1024)

        info = f"Size: {size:,} bytes ({size_mb:.2f} MB)"

        if size_mb > 500 and STREAMING_AVAILABLE:
            info += " - Consider streaming analysis"
            self.file_info_label.config(foreground="#ffc107")
        else:
            self.file_info_label.config(foreground="#666666")

        self.file_info_label.config(text=info)

    def start_analysis(self):
        """Start binary analysis"""
        if not self.binary_path.get():
            messagebox.showerror("Error", "Please select a binary file first")
            return

        if not Path(self.binary_path.get()).exists():
            messagebox.showerror("Error", "Selected file does not exist")
            return

        if self.is_analyzing:
            messagebox.showwarning("Warning", "Analysis already in progress")
            return

        # Clear previous results
        self.clear_results()

        # Reset progress
        self.progress_value.set(0)
        self.progress_text.set("Initializing...")
        self.analysis_start_time = time.time()

        # Disable analyze button
        self.analyze_btn.config(state=tk.DISABLED)
        self.is_analyzing = True

        # Run analysis in background thread
        thread = threading.Thread(target=self.run_analysis_async, daemon=True)
        thread.start()

        # Update timestamp
        self.update_timestamp()

    def run_analysis_async(self):
        """Run analysis asynchronously with progress updates"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            mode = self.analysis_mode.get()
            binary_path = self.binary_path.get()

            self.update_status(f"Analyzing {Path(binary_path).name}...")

            if mode == "quick":
                loop.run_until_complete(self.analyze_quick(binary_path))
            elif mode == "standard":
                loop.run_until_complete(self.analyze_standard(binary_path))
            elif mode == "deep":
                loop.run_until_complete(self.analyze_deep(binary_path))
            elif mode == "streaming" and STREAMING_AVAILABLE:
                loop.run_until_complete(self.analyze_streaming(binary_path))

            # Update statistics
            duration = time.time() - self.analysis_start_time
            self.stats_labels['duration'].set(f"{duration:.2f}s")
            file_size_mb = Path(binary_path).stat().st_size / (1024 * 1024)
            self.stats_labels['file_size'].set(f"{file_size_mb:.2f} MB")

            current_count = int(self.stats_labels['analyses'].get())
            self.stats_labels['analyses'].set(str(current_count + 1))

            self.update_status("Analysis complete ✅")
            self.progress_value.set(100)
            self.progress_text.set(f"Complete! (took {duration:.2f}s)")

            messagebox.showinfo("Success", f"Binary analysis completed successfully!\n\nDuration: {duration:.2f}s")

        except Exception as e:
            self.update_status(f"Error: {str(e)}")
            self.progress_text.set(f"Error: {str(e)}")
            messagebox.showerror("Analysis Error", f"An error occurred:\n\n{str(e)}")

        finally:
            self.analyze_btn.config(state=tk.NORMAL)
            self.is_analyzing = False
            self.update_timestamp()

    async def analyze_quick(self, binary_path: str):
        """Quick analysis with progress"""
        self.update_progress(20, "Parsing binary headers...")

        metadata, _, _, _, _ = await asyncio.to_thread(
            analyze_binary_with_lief,
            binary_path
        )

        self.results['metadata'] = metadata
        self.results['analysis_type'] = 'quick'

        self.update_progress(100, "Quick analysis complete")
        self.display_results()

    async def analyze_standard(self, binary_path: str):
        """Standard analysis with progress"""
        self.update_progress(10, "Parsing binary structure...")

        metadata, symbols, imports, exports, elf_info = await asyncio.to_thread(
            analyze_binary_with_lief,
            binary_path
        )

        self.results['metadata'] = metadata
        self.results['symbols'] = symbols
        self.results['imports'] = imports
        self.results['exports'] = exports
        self.results['analysis_type'] = 'standard'

        self.update_progress(60, "Running YARA scan...")

        yara_results = await asyncio.to_thread(
            scan_with_yara_rules,
            binary_path
        )
        self.results['yara'] = yara_results

        self.update_progress(100, "Standard analysis complete")
        self.display_results()

    async def analyze_deep(self, binary_path: str):
        """Deep analysis with progress"""
        await self.analyze_standard(binary_path)

        self.update_progress(70, "Running Ghidra decompilation (this is slow)...")

        try:
            ghidra_result = await asyncio.to_thread(
                analyze_binary_with_ghidra,
                binary_path,
                timeout=300
            )
            self.results['ghidra'] = ghidra_result
            self.results['analysis_type'] = 'deep'
        except Exception as e:
            self.results['ghidra_error'] = str(e)

        self.update_progress(100, "Deep analysis complete")
        self.display_results()

    async def analyze_streaming(self, binary_path: str):
        """Streaming analysis for large files"""
        if not STREAMING_AVAILABLE:
            raise Exception("Streaming analysis not available")

        self.update_progress(5, "Initializing streaming analysis...")

        def progress_callback(bytes_processed, total_bytes):
            percentage = int((bytes_processed / total_bytes) * 90) + 5  # 5-95%
            self.update_progress(percentage, f"Processing: {bytes_processed:,} / {total_bytes:,} bytes")

        result = await streaming_analyzer.analyze_large_binary_streaming(
            binary_path,
            analysis_type="standard",
            progress_callback=progress_callback
        )

        self.results = result
        self.results['analysis_type'] = 'streaming'

        self.update_progress(100, "Streaming analysis complete")
        self.display_results()

    def display_results(self):
        """Display analysis results with color coding"""
        # Summary
        summary = self.generate_summary()
        self.summary_text.delete(1.0, tk.END)
        self.summary_text.insert(1.0, summary)

        # Metadata with syntax highlighting
        if 'metadata' in self.results:
            metadata_str = json.dumps(self.results['metadata'], indent=2, default=str)
            self.metadata_text.delete(1.0, tk.END)
            self.metadata_text.insert(1.0, metadata_str)

        # Imports
        if 'imports' in self.results:
            imports_str = self.format_imports()
            self.imports_text.delete(1.0, tk.END)
            self.imports_text.insert(1.0, imports_str)

        # YARA with color coding
        if 'yara' in self.results:
            yara_str = self.format_yara_results()
            self.yara_text.delete(1.0, tk.END)
            self.yara_text.insert(1.0, yara_str)

        # Decompilation
        if 'ghidra' in self.results:
            decomp_str = json.dumps(self.results['ghidra'], indent=2, default=str)
            self.decomp_text.delete(1.0, tk.END)
            self.decomp_text.insert(1.0, decomp_str)
        elif 'ghidra_error' in self.results:
            self.decomp_text.delete(1.0, tk.END)
            self.decomp_text.insert(1.0, f"Decompilation failed: {self.results['ghidra_error']}")

    def generate_summary(self) -> str:
        """Generate enhanced summary"""
        summary = "=" * 80 + "\n"
        summary += "BINARY ANALYSIS SUMMARY\n"
        summary += "=" * 80 + "\n\n"

        if 'metadata' in self.results:
            metadata = self.results['metadata']
            summary += f"File: {self.binary_path.get()}\n"
            summary += f"Analysis Type: {self.results.get('analysis_type', 'unknown').upper()}\n"
            summary += f"Type: {metadata.get('file_type', 'Unknown')}\n"
            summary += f"Architecture: {metadata.get('architecture', 'Unknown')}\n"
            summary += f"Size: {metadata.get('file_size', 0):,} bytes\n"
            summary += f"Entry Point: 0x{metadata.get('entry_point', 0):x}\n"

            is_packed = metadata.get('is_packed')
            summary += f"Packed: {'[WARNING] Yes - Possible obfuscation' if is_packed else 'No'}\n\n"

        if 'imports' in self.results:
            summary += f"Imported Functions: {len(self.results['imports'])}\n"

        if 'exports' in self.results:
            summary += f"Exported Functions: {len(self.results['exports'])}\n"

        if 'yara' in self.results:
            yara_count = len(self.results['yara'])
            summary += f"\nYARA Matches: {yara_count}\n"
            if yara_count > 0:
                summary += "[WARNING] Potential security issues detected!\n\n"
                summary += "Detected Issues:\n"
                for match in self.results['yara']:
                    severity = match.get('meta', {}).get('severity', 'unknown')
                    summary += f"  [{severity.upper()}] {match.get('rule')}\n"
            else:
                summary += "[OK] No YARA matches - Binary appears clean\n"

        if 'ghidra' in self.results:
            functions = len(self.results['ghidra'].get('functions', []))
            summary += f"\nDecompiled Functions: {functions}\n"

        duration = self.results.get('duration_seconds')
        if duration:
            summary += f"\nAnalysis Duration: {duration:.2f} seconds\n"

        summary += "\n" + "=" * 80 + "\n"
        summary += f"Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        summary += "=" * 80 + "\n"

        return summary

    def format_imports(self) -> str:
        """Format imports with categories"""
        imports = self.results.get('imports', [])
        if not imports:
            return "No imports found"

        output = f"Total Imported Functions: {len(imports)}\n\n"
        output += "-" * 80 + "\n\n"

        # Group by library
        libraries = {}
        for imp in imports[:200]:  # Limit to first 200
            lib = imp.get('library', 'Unknown')
            func = imp.get('name', 'Unknown')
            if lib not in libraries:
                libraries[lib] = []
            libraries[lib].append(func)

        for lib, funcs in sorted(libraries.items()):
            output += f"{lib} ({len(funcs)} functions)\n"
            for func in funcs[:50]:  # Limit functions per library
                output += f"  - {func}\n"
            if len(funcs) > 50:
                output += f"  ... and {len(funcs) - 50} more\n"
            output += "\n"

        if len(imports) > 200:
            output += f"\n... and {len(imports) - 200} more imports\n"

        return output

    def format_yara_results(self) -> str:
        """Format YARA results with severity indicators"""
        yara_results = self.results.get('yara', [])

        if not yara_results:
            return "✅ No YARA matches found\n\nBinary appears clean based on signature analysis."

        output = f"⚠️  YARA MATCHES FOUND: {len(yara_results)}\n\n"
        output += "=" * 80 + "\n\n"

        for match in yara_results:
            rule = match.get('rule', 'Unknown')
            severity = match.get('meta', {}).get('severity', 'unknown').upper()
            description = match.get('meta', {}).get('description', 'No description')

            severity_indicator = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🟢',
            }.get(severity, '⚪')

            output += f"{severity_indicator} [{severity}] {rule}\n"
            output += f"Description: {description}\n"
            output += "-" * 80 + "\n\n"

        return output

    async def update_cache_stats(self):
        """Update cache statistics display"""
        if not CACHE_AVAILABLE:
            return

        try:
            stats = await enhanced_cache.get_stats()
            hit_rate = stats.get('hit_rate_percent', 0)

            self.cache_hit_rate.set(f"{hit_rate:.1f}%")

            # Color code hit rate
            if hit_rate > 70:
                self.cache_hit_label.config(foreground="#28a745")  # Green
            elif hit_rate > 50:
                self.cache_hit_label.config(foreground="#ffc107")  # Yellow
            else:
                self.cache_hit_label.config(foreground="#dc3545")  # Red

            operations = f"Hits: {stats.get('hits', 0):,}\nMisses: {stats.get('misses', 0):,}"
            self.cache_operations.set(operations)

        except Exception as e:
            self.cache_hit_rate.set("Error")
            self.cache_operations.set(str(e))

    def export_results(self):
        """Export results to file"""
        if not self.results:
            messagebox.showwarning("Warning", "No analysis results to export")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            initialfile=f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            filetypes=[
                ("JSON Files", "*.json"),
                ("Text Files", "*.txt"),
                ("Markdown Files", "*.md"),
                ("All Files", "*.*")
            ]
        )

        if filename:
            try:
                with open(filename, 'w') as f:
                    if filename.endswith('.json'):
                        json.dump(self.results, f, indent=2, default=str)
                    elif filename.endswith('.md'):
                        f.write("# Binary Analysis Report\n\n")
                        f.write(self.generate_summary())
                    else:
                        f.write(self.generate_summary())
                        f.write("\n\nDetailed Results:\n")
                        f.write(json.dumps(self.results, indent=2, default=str))

                messagebox.showinfo("Success", f"Results exported to:\n{filename}")
                self.update_status(f"Exported to {Path(filename).name}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export results:\n{str(e)}")

    def clear_results(self):
        """Clear all results"""
        self.results = {}
        self.summary_text.delete(1.0, tk.END)
        self.metadata_text.delete(1.0, tk.END)
        self.imports_text.delete(1.0, tk.END)
        self.yara_text.delete(1.0, tk.END)
        self.decomp_text.delete(1.0, tk.END)
        self.progress_value.set(0)
        self.progress_text.set("Ready")

    def update_status(self, message: str):
        """Update status bar message"""
        self.root.after(0, lambda: self.status_label.config(text=message))

    def update_progress(self, value: int, text: str):
        """Update progress bar and text"""
        self.root.after(0, lambda: self.progress_value.set(value))
        self.root.after(0, lambda: self.progress_text.set(text))

    def update_timestamp(self):
        """Update timestamp in status bar"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.timestamp_label.config(text=timestamp)


def main():
    """Entry point"""
    root = tk.Tk()
    app = EnhancedBinaryAnalyzerGUI(root)

    # Initialize cache stats if available
    if CACHE_AVAILABLE:
        root.after(1000, lambda: asyncio.run(app.update_cache_stats()))

    root.mainloop()


if __name__ == "__main__":
    main()
