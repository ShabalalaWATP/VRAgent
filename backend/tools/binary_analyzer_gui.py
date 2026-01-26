#!/usr/bin/env python3
"""
Binary Analyzer - Desktop GUI Application
Simple desktop application for binary analysis with drag-and-drop support
"""

import asyncio
import json
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime

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


class BinaryAnalyzerGUI:
    """Desktop GUI for binary analysis"""

    def __init__(self, root):
        self.root = root
        self.root.title("VRAgent Binary Analyzer - GUI Mode")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)

        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')  # Modern theme

        # Variables
        self.binary_path = tk.StringVar()
        self.analysis_mode = tk.StringVar(value="standard")
        self.results: Dict[str, Any] = {}
        self.is_analyzing = False

        self.setup_ui()

    def setup_ui(self):
        """Setup the user interface"""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)

        # Header
        self.create_header(main_frame)

        # File selection section
        self.create_file_section(main_frame)

        # Results section
        self.create_results_section(main_frame)

        # Status bar
        self.create_status_bar(main_frame)

    def create_header(self, parent):
        """Create header section"""
        header_frame = ttk.Frame(parent)
        header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 20))

        title_label = ttk.Label(
            header_frame,
            text="🔬 VRAgent Binary Analyzer",
            font=("Arial", 18, "bold"),
            foreground="#0066cc"
        )
        title_label.grid(row=0, column=0, sticky=tk.W)

        subtitle_label = ttk.Label(
            header_frame,
            text="Comprehensive Binary Security Analysis",
            font=("Arial", 10),
            foreground="#666666"
        )
        subtitle_label.grid(row=1, column=0, sticky=tk.W)

    def create_file_section(self, parent):
        """Create file selection and analysis controls"""
        file_frame = ttk.LabelFrame(parent, text="Binary Selection & Analysis", padding="10")
        file_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        file_frame.columnconfigure(1, weight=1)

        # File path
        ttk.Label(file_frame, text="Binary File:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))

        file_entry = ttk.Entry(file_frame, textvariable=self.binary_path, width=50)
        file_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))

        browse_btn = ttk.Button(file_frame, text="Browse...", command=self.browse_file)
        browse_btn.grid(row=0, column=2)

        # Analysis mode
        ttk.Label(file_frame, text="Analysis Mode:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(10, 0))

        mode_frame = ttk.Frame(file_frame)
        mode_frame.grid(row=1, column=1, sticky=tk.W, pady=(10, 0))

        ttk.Radiobutton(
            mode_frame,
            text="Quick (Fast, basic info)",
            variable=self.analysis_mode,
            value="quick"
        ).pack(side=tk.LEFT, padx=(0, 20))

        ttk.Radiobutton(
            mode_frame,
            text="Standard (Recommended)",
            variable=self.analysis_mode,
            value="standard"
        ).pack(side=tk.LEFT, padx=(0, 20))

        ttk.Radiobutton(
            mode_frame,
            text="Deep (Full decompilation)",
            variable=self.analysis_mode,
            value="deep"
        ).pack(side=tk.LEFT)

        # Action buttons
        button_frame = ttk.Frame(file_frame)
        button_frame.grid(row=2, column=0, columnspan=3, pady=(15, 0))

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
        """Create results display section"""
        results_frame = ttk.LabelFrame(parent, text="Analysis Results", padding="10")
        results_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)

        # Notebook for tabbed results
        self.notebook = ttk.Notebook(results_frame)
        self.notebook.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Summary tab
        self.summary_text = scrolledtext.ScrolledText(
            self.notebook,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg="#f5f5f5"
        )
        self.notebook.add(self.summary_text, text="📊 Summary")

        # Metadata tab
        self.metadata_text = scrolledtext.ScrolledText(
            self.notebook,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg="#f5f5f5"
        )
        self.notebook.add(self.metadata_text, text="📋 Metadata")

        # Imports tab
        self.imports_text = scrolledtext.ScrolledText(
            self.notebook,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg="#f5f5f5"
        )
        self.notebook.add(self.imports_text, text="📥 Imports")

        # YARA tab
        self.yara_text = scrolledtext.ScrolledText(
            self.notebook,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg="#f5f5f5"
        )
        self.notebook.add(self.yara_text, text="🔍 YARA Matches")

        # Decompilation tab
        self.decomp_text = scrolledtext.ScrolledText(
            self.notebook,
            wrap=tk.WORD,
            font=("Consolas", 8),
            bg="#f5f5f5"
        )
        self.notebook.add(self.decomp_text, text="🔬 Decompilation")

        # Progress bar
        self.progress = ttk.Progressbar(results_frame, mode='indeterminate')
        self.progress.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(10, 0))

    def create_status_bar(self, parent):
        """Create status bar"""
        status_frame = ttk.Frame(parent)
        status_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(10, 0))

        self.status_label = ttk.Label(
            status_frame,
            text="Ready",
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        self.status_label.pack(fill=tk.X)

    def browse_file(self):
        """Open file browser dialog"""
        filename = filedialog.askopenfilename(
            title="Select Binary File",
            filetypes=[
                ("Executable Files", "*.exe;*.dll;*.so;*.elf;*.bin"),
                ("All Files", "*.*")
            ]
        )
        if filename:
            self.binary_path.set(filename)

    def start_analysis(self):
        """Start binary analysis in background thread"""
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

        # Disable analyze button
        self.analyze_btn.config(state=tk.DISABLED)
        self.is_analyzing = True

        # Start progress bar
        self.progress.start()

        # Run analysis in background thread
        thread = threading.Thread(target=self.run_analysis_async, daemon=True)
        thread.start()

    def run_analysis_async(self):
        """Run analysis asynchronously"""
        try:
            # Create new event loop for this thread
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

            self.update_status("Analysis complete ✅")
            messagebox.showinfo("Success", "Binary analysis completed successfully!")

        except Exception as e:
            self.update_status(f"Error: {str(e)}")
            messagebox.showerror("Analysis Error", f"An error occurred:\n\n{str(e)}")

        finally:
            self.progress.stop()
            self.analyze_btn.config(state=tk.NORMAL)
            self.is_analyzing = False

    async def analyze_quick(self, binary_path: str):
        """Quick analysis"""
        metadata, _, _, _, _ = await asyncio.to_thread(
            analyze_binary_with_lief,
            binary_path
        )
        self.results['metadata'] = metadata
        self.display_results()

    async def analyze_standard(self, binary_path: str):
        """Standard analysis"""
        metadata, symbols, imports, exports, elf_info = await asyncio.to_thread(
            analyze_binary_with_lief,
            binary_path
        )
        self.results['metadata'] = metadata
        self.results['symbols'] = symbols
        self.results['imports'] = imports
        self.results['exports'] = exports

        # YARA scan
        yara_results = await asyncio.to_thread(
            scan_with_yara_rules,
            binary_path
        )
        self.results['yara'] = yara_results

        self.display_results()

    async def analyze_deep(self, binary_path: str):
        """Deep analysis with decompilation"""
        await self.analyze_standard(binary_path)

        # Ghidra decompilation
        try:
            ghidra_result = await asyncio.to_thread(
                analyze_binary_with_ghidra,
                binary_path,
                timeout=300
            )
            self.results['ghidra'] = ghidra_result
        except Exception as e:
            self.results['ghidra_error'] = str(e)

        self.display_results()

    def display_results(self):
        """Display analysis results in GUI"""
        # Summary
        summary = self.generate_summary()
        self.summary_text.delete(1.0, tk.END)
        self.summary_text.insert(1.0, summary)

        # Metadata
        if 'metadata' in self.results:
            metadata_str = json.dumps(self.results['metadata'], indent=2, default=str)
            self.metadata_text.delete(1.0, tk.END)
            self.metadata_text.insert(1.0, metadata_str)

        # Imports
        if 'imports' in self.results:
            imports_str = "\n".join(
                f"{imp.get('library', 'Unknown')}: {imp.get('name', 'Unknown')}"
                for imp in self.results['imports'][:100]
            )
            if len(self.results['imports']) > 100:
                imports_str += f"\n\n... and {len(self.results['imports']) - 100} more"
            self.imports_text.delete(1.0, tk.END)
            self.imports_text.insert(1.0, imports_str)

        # YARA
        if 'yara' in self.results:
            if self.results['yara']:
                yara_str = "\n\n".join(
                    f"Rule: {match.get('rule', 'Unknown')}\n"
                    f"Description: {match.get('meta', {}).get('description', 'N/A')}\n"
                    f"Severity: {match.get('meta', {}).get('severity', 'unknown').upper()}"
                    for match in self.results['yara']
                )
            else:
                yara_str = "✅ No YARA matches found (binary appears clean)"
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
        """Generate analysis summary"""
        summary = "=" * 70 + "\n"
        summary += "BINARY ANALYSIS SUMMARY\n"
        summary += "=" * 70 + "\n\n"

        if 'metadata' in self.results:
            metadata = self.results['metadata']
            summary += f"File: {self.binary_path.get()}\n"
            summary += f"Type: {metadata.get('file_type', 'Unknown')}\n"
            summary += f"Architecture: {metadata.get('architecture', 'Unknown')}\n"
            summary += f"Size: {metadata.get('file_size', 0):,} bytes\n"
            summary += f"Entry Point: 0x{metadata.get('entry_point', 0):x}\n"
            summary += f"Packed: {'Yes' if metadata.get('is_packed') else 'No'}\n\n"

        if 'imports' in self.results:
            summary += f"Imported Functions: {len(self.results['imports'])}\n"

        if 'exports' in self.results:
            summary += f"Exported Functions: {len(self.results['exports'])}\n"

        if 'yara' in self.results:
            summary += f"\nYARA Matches: {len(self.results['yara'])}\n"
            if self.results['yara']:
                summary += "\nDetected Issues:\n"
                for match in self.results['yara']:
                    severity = match.get('meta', {}).get('severity', 'unknown')
                    summary += f"  - {match.get('rule')}: {severity.upper()}\n"

        if 'ghidra' in self.results:
            summary += f"\nDecompiled Functions: {len(self.results['ghidra'].get('functions', []))}\n"

        summary += "\n" + "=" * 70 + "\n"
        summary += f"Analysis completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        summary += "=" * 70 + "\n"

        return summary

    def export_results(self):
        """Export results to file"""
        if not self.results:
            messagebox.showwarning("Warning", "No analysis results to export")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[
                ("JSON Files", "*.json"),
                ("Text Files", "*.txt"),
                ("All Files", "*.*")
            ]
        )

        if filename:
            try:
                with open(filename, 'w') as f:
                    if filename.endswith('.json'):
                        json.dump(self.results, f, indent=2, default=str)
                    else:
                        f.write(self.generate_summary())
                        f.write("\n\nDetailed Results:\n")
                        f.write(json.dumps(self.results, indent=2, default=str))

                messagebox.showinfo("Success", f"Results exported to:\n{filename}")
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

    def update_status(self, message: str):
        """Update status bar message"""
        self.root.after(0, lambda: self.status_label.config(text=message))


def main():
    """Entry point"""
    root = tk.Tk()
    app = BinaryAnalyzerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
