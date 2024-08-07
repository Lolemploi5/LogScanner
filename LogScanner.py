import os
import re
import json
import matplotlib.pyplot as plt
from collections import defaultdict
from typing import Dict
from colorama import init, Fore, Style
from tqdm import tqdm
import concurrent.futures

init(autoreset=True)

print(f"""{Fore.RED}    
██╗      ██████╗  ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██║     ██╔═══██╗██╔════╝ ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗ 
██║     ██║   ██║██║  ███╗███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝ 
██║     ██║   ██║██║   ██║╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗  
███████╗╚██████╔╝╚██████╔╝███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║ 
╚══════╝ ╚═════╝  ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ 
""" + Style.RESET_ALL)

class LogScanner:
    def __init__(self, log_directory: str, config_file: str, solutions_file: str):
        self.log_directory = log_directory
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
                print(f"{color}{severity}: {count} occurences{Style.RESET_ALL}")

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

def main():
    log_directory = 'logscan'
    config_file = 'config/config.json'
    solutions_file = 'config/error_solutions.json'

    if not os.path.exists(log_directory):
        print(f"{Fore.RED}The directory '{log_directory}' does not exist.{Style.RESET_ALL}")
        return

    if not os.path.exists(config_file):
        print(f"{Fore.RED}Configuration file '{config_file}' not found.{Style.RESET_ALL}")
        return

    if not os.path.exists(solutions_file):
        print(f"{Fore.RED}Solutions file '{solutions_file}' not found.{Style.RESET_ALL}")
        return

    files = [f for f in os.listdir(log_directory) if f.endswith('.log')]
    if not files:
        print(f"{Fore.RED}No log files found in '{log_directory}'.{Style.RESET_ALL}")
        return

    print("Available log files:")
    for i, file in enumerate(files):
        print(f"{i + 1}. {file}")

    choice = input("Enter the number of the file to scan, 'all' to scan all files, or a comma-separated list of numbers to scan multiple files: ")

    if choice == 'all':
        selected_files = [os.path.join(log_directory, file) for file in files]
    else:
        try:
            selected_indices = [int(i) for i in choice.split(',')]
            selected_files = [os.path.join(log_directory, files[i - 1]) for i in selected_indices if 1 <= i <= len(files)]
        except ValueError:
            print(f"{Fore.RED}Invalid input.{Style.RESET_ALL}")
            return

    scanner = LogScanner(log_directory, config_file, solutions_file)
    scanner.scan_logs(selected_files)
    scanner.print_report()

    severity_choice = input("Enter the severity level to display lines (e.g., ERROR, WARNING, INFO, DEBUG): ").strip()
    scanner.display_severity_lines(severity_choice.upper())

if __name__ == '__main__':
    main()
