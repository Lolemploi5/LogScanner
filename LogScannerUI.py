import os
import re
import json
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from collections import defaultdict
from typing import Dict
from colorama import init, Fore, Style
import matplotlib.pyplot as plt
from tqdm import tqdm
import concurrent.futures

init(autoreset=True)

class LogScanner:
    def __init__(self, config_file: str, solutions_file: str):
        self.patterns = {}
        self.severity_levels = defaultdict(int)
        self.solutions = {}
        self.lines_by_severity = defaultdict(list)
        self.suggestions = defaultdict(list)
        self.files_stats = defaultdict(lambda: defaultdict(int))
        self.load_config(config_file)
        self.load_solutions(solutions_file)

    def load_config(self, config_file: str):
        try:
            with open(config_file, 'r') as file:
                config = json.load(file)
                for name, pattern in config.get("patterns", {}).items():
                    self.add_pattern(name, pattern)
        except Exception as e:
            print(f"{Fore.RED}Error loading configuration file {config_file}: {e}{Style.RESET_ALL}")

    def load_solutions(self, solutions_file: str):
        try:
            with open(solutions_file, 'r') as file:
                self.solutions = json.load(file)
        except Exception as e:
            print(f"{Fore.RED}Error loading solutions file {solutions_file}: {e}{Style.RESET_ALL}")

    def add_pattern(self, name: str, pattern: str):
        self.patterns[name] = re.compile(pattern)

    def scan_logs(self, files):
        with concurrent.futures.ThreadPoolExecutor() as executor:
            list(tqdm(executor.map(self._process_file, files), total=len(files), desc="Scanning files"))

    def _process_file(self, file_path: str):
        try:
            with open(file_path, 'r') as file:
                lines = file.readlines()
                for line in tqdm(lines, desc=f"Processing {os.path.basename(file_path)}", unit="line"):
                    self._process_line(line, os.path.basename(file_path))
        except Exception as e:
            print(f"{Fore.RED}Error reading {file_path}: {e}{Style.RESET_ALL}")

    def _process_line(self, line: str, file_name: str):
        for name, pattern in self.patterns.items():
            if pattern.search(line):
                self.severity_levels[name] += 1
                self.lines_by_severity[name].append(line.strip())
                self.files_stats[file_name][name] += 1
                self._suggest_solution(name, line)

    def _suggest_solution(self, severity: str, line: str):
        for error_type, solutions in self.solutions.get(severity, {}).items():
            if error_type in line:
                self.suggestions[severity].append((error_type, solutions))

    def generate_report(self) -> Dict[str, int]:
        return dict(self.severity_levels)

    def print_report(self):
        report = self.generate_report()
        for severity, count in report.items():
            color = self._get_severity_color(severity)
            print(f"{color}{severity}: {count} occurrences{Style.RESET_ALL}")
        self.print_suggestions()
        self.print_statistics()

    def print_suggestions(self):
        for severity, suggestions in self.suggestions.items():
            print(f"\n{self._get_severity_color(severity)}Suggestions for {severity}:{Style.RESET_ALL}")
            for error_type, solution in suggestions:
                print(f"{Fore.CYAN}Error: {error_type}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Solution: {solution}{Style.RESET_ALL}")

    def print_statistics(self):
        print("\nStatistics by file:")
        for file_name, stats in self.files_stats.items():
            print(f"\n{Fore.BLUE}{file_name}{Style.RESET_ALL}")
            for severity, count in stats.items():
                color = self._get_severity_color(severity)
                print(f"{color}{severity}: {count}{Style.RESET_ALL}")

        self.plot_statistics()

    def plot_statistics(self):
        severities = list(self.severity_levels.keys())
        counts = list(self.severity_levels.values())
        plt.bar(severities, counts, color=['red', 'yellow', 'green', 'cyan'])
        plt.xlabel('Severity')
        plt.ylabel('Count')
        plt.title('Log Severity Distribution')
        plt.show()

    def _get_severity_color(self, severity: str) -> str:
        color_map = {
            'ERROR': Fore.RED,
            'WARNING': Fore.YELLOW,
            'INFO': Fore.GREEN,
            'DEBUG': Fore.CYAN
        }
        return color_map.get(severity, Fore.WHITE)

    def display_severity_lines(self, severity: str):
        if severity in self.lines_by_severity:
            print(f"\n{self._get_severity_color(severity)}Lines with {severity}:{Style.RESET_ALL}")
            for line in self.lines_by_severity[severity]:
                print(line)
        else:
            print(f"{Fore.RED}No lines found for severity level {severity}.{Style.RESET_ALL}")

class LogScannerUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Log Scanner UI by Lolemploi5")

        self.config_file = ""
        self.solutions_file = ""
        self.selected_files = []

        self.create_widgets()

    def create_widgets(self):
        frame = ttk.Frame(self.root, padding="10")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        ttk.Label(frame, text="Configuration File:").grid(row=0, column=0, sticky=tk.W)
        self.config_entry = ttk.Entry(frame, width=50)
        self.config_entry.grid(row=0, column=1, sticky=(tk.W, tk.E))
        ttk.Button(frame, text="Browse", command=self.browse_config).grid(row=0, column=2, sticky=tk.W)

        ttk.Label(frame, text="Solutions File:").grid(row=1, column=0, sticky=tk.W)
        self.solutions_entry = ttk.Entry(frame, width=50)
        self.solutions_entry.grid(row=1, column=1, sticky=(tk.W, tk.E))
        ttk.Button(frame, text="Browse", command=self.browse_solutions).grid(row=1, column=2, sticky=tk.W)

        ttk.Label(frame, text="Select Log Files:").grid(row=2, column=0, sticky=tk.W)
        ttk.Button(frame, text="Browse", command=self.browse_files).grid(row=2, column=1, sticky=tk.W)

        self.file_listbox = tk.Listbox(frame, selectmode=tk.MULTIPLE, width=50, height=10)
        self.file_listbox.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E))

        ttk.Button(frame, text="Scan Logs", command=self.scan_logs).grid(row=4, column=0, columnspan=3)

        self.report_text = tk.Text(frame, width=80, height=20)
        self.report_text.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E))

        ttk.Button(frame, text="Show Severity Lines", command=self.show_severity_lines).grid(row=6, column=0, columnspan=3)

    def browse_config(self):
        self.config_file = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        self.config_entry.delete(0, tk.END)
        self.config_entry.insert(0, self.config_file)

    def browse_solutions(self):
        self.solutions_file = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        self.solutions_entry.delete(0, tk.END)
        self.solutions_entry.insert(0, self.solutions_file)

    def browse_files(self):
        self.selected_files = filedialog.askopenfilenames(filetypes=[("Log files", "*.log")])
        self.file_listbox.delete(0, tk.END)
        for file in self.selected_files:
            self.file_listbox.insert(tk.END, file)

    def scan_logs(self):
        if not self.config_file or not self.solutions_file or not self.selected_files:
            messagebox.showerror("Error", "Please select all necessary files.")
            return

        scanner = LogScanner(self.config_file, self.solutions_file)
        scanner.scan_logs(self.selected_files)
        self.report_text.delete(1.0, tk.END)
        report = scanner.generate_report()
        for severity, count in report.items():
            self.report_text.insert(tk.END, f"{severity}: {count} occurrences\n")
        scanner.print_suggestions()
        scanner.print_statistics()

    def show_severity_lines(self):
        severity = tk.simpledialog.askstring("Input", "Enter the severity level to display lines (e.g., ERROR, WARNING, INFO, DEBUG):")
        if severity:
            scanner = LogScanner(self.config_file, self.solutions_file)
            scanner.scan_logs(self.selected_files)
            lines = scanner.lines_by_severity.get(severity.upper(), [])
            self.report_text.delete(1.0, tk.END)
            for line in lines:
                self.report_text.insert(tk.END, line + "\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = LogScannerUI(root)
    root.mainloop()
