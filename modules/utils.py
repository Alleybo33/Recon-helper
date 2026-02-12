#!/usr/bin/env python3
"""
Core Utilities Module
Provides logging, configuration, and utility functions
"""

import os
import sys
import yaml
import json
import logging
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Union, Any
from logging.handlers import RotatingFileHandler
import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)

class ReconLogger:
    """Enhanced logging with colors and file rotation"""
    
    def __init__(self, name: str, log_dir: str = "logs", level: str = "INFO"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        
        # Create logs directory
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        
        # File handler with rotation
        log_file = os.path.join(log_dir, f"{name}_{datetime.now().strftime('%Y%m%d')}.log")
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=100*1024*1024,  # 100MB
            backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        
        # Console handler with colors
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(ColoredFormatter())
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def get_logger(self):
        return self.logger


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors"""
    
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT,
    }
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, '')
        record.levelname = f"{log_color}{record.levelname}{Style.RESET_ALL}"
        record.msg = f"{log_color}{record.msg}{Style.RESET_ALL}"
        return super().format(record)


class ConfigLoader:
    """Load and validate configuration"""
    
    def __init__(self, config_path: str = "config/config.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
    
    def _load_config(self) -> Dict:
        """Load YAML configuration file"""
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            return config
        except FileNotFoundError:
            print(f"[ERROR] Config file not found: {self.config_path}")
            sys.exit(1)
        except yaml.YAMLError as e:
            print(f"[ERROR] Invalid YAML in config file: {e}")
            sys.exit(1)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value with dot notation"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k, default)
            else:
                return default
        
        return value
    
    def get_target(self) -> str:
        """Get target domain"""
        return self.config.get('target', {}).get('domain', 'example.com')
    
    def get_output_dir(self) -> str:
        """Get output directory"""
        return self.config.get('directories', {}).get('output', 'output')


class CommandExecutor:
    """Execute shell commands with logging and error handling"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def run(self, command: Union[str, List[str]], 
            capture_output: bool = True,
            timeout: Optional[int] = None,
            check: bool = True,
            shell: bool = True) -> subprocess.CompletedProcess:
        """Execute command and return result"""
        
        if isinstance(command, list):
            cmd_str = ' '.join(command)
        else:
            cmd_str = command
        
        self.logger.info(f"Executing: {cmd_str}")
        
        try:
            result = subprocess.run(
                command,
                capture_output=capture_output,
                text=True,
                timeout=timeout,
                check=check,
                shell=shell
            )
            
            if result.returncode == 0:
                self.logger.debug(f"Command successful: {cmd_str}")
            else:
                self.logger.warning(f"Command returned non-zero: {cmd_str}")
            
            return result
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"Command timed out: {cmd_str}")
            raise
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command failed: {cmd_str}\nError: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error: {cmd_str}\nError: {e}")
            raise
    
    def run_silent(self, command: str, timeout: Optional[int] = None) -> bool:
        """Run command silently and return success status"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=True
            )
            return result.returncode == 0
        except Exception:
            return False


class FileManager:
    """Manage files and directories"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def create_directory(self, path: str) -> Path:
        """Create directory if it doesn't exist"""
        dir_path = Path(path)
        dir_path.mkdir(parents=True, exist_ok=True)
        self.logger.debug(f"Created directory: {path}")
        return dir_path
    
    def merge_files(self, input_files: List[str], output_file: str, 
                   remove_duplicates: bool = True) -> int:
        """Merge multiple files and optionally remove duplicates"""
        
        all_lines = set() if remove_duplicates else []
        
        for file_path in input_files:
            if not os.path.exists(file_path):
                self.logger.warning(f"File not found: {file_path}")
                continue
            
            try:
                with open(file_path, 'r') as f:
                    lines = f.readlines()
                    
                if remove_duplicates:
                    all_lines.update(line.strip() for line in lines if line.strip())
                else:
                    all_lines.extend(line.strip() for line in lines if line.strip())
                    
            except Exception as e:
                self.logger.error(f"Error reading {file_path}: {e}")
        
        # Write merged results
        try:
            with open(output_file, 'w') as f:
                if remove_duplicates:
                    sorted_lines = sorted(all_lines)
                    f.write('\n'.join(sorted_lines))
                else:
                    f.write('\n'.join(all_lines))
            
            count = len(all_lines)
            self.logger.info(f"Merged {len(input_files)} files into {output_file} ({count} entries)")
            return count
            
        except Exception as e:
            self.logger.error(f"Error writing to {output_file}: {e}")
            return 0
    
    def read_file_lines(self, file_path: str) -> List[str]:
        """Read file and return non-empty lines"""
        try:
            with open(file_path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.logger.error(f"Error reading {file_path}: {e}")
            return []
    
    def write_file_lines(self, file_path: str, lines: List[str]) -> bool:
        """Write lines to file"""
        try:
            with open(file_path, 'w') as f:
                f.write('\n'.join(lines))
            return True
        except Exception as e:
            self.logger.error(f"Error writing to {file_path}: {e}")
            return False
    
    def count_lines(self, file_path: str) -> int:
        """Count lines in file"""
        try:
            with open(file_path, 'r') as f:
                return sum(1 for line in f if line.strip())
        except Exception:
            return 0
    
    def file_exists(self, file_path: str) -> bool:
        """Check if file exists and is not empty"""
        return os.path.exists(file_path) and os.path.getsize(file_path) > 0


class ToolChecker:
    """Check if required tools are installed"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def check_tool(self, tool_name: str, version_flag: str = "--version") -> bool:
        """Check if a tool is installed"""
        try:
            result = subprocess.run(
                f"{tool_name} {version_flag}",
                capture_output=True,
                text=True,
                shell=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def check_required_tools(self, tools: List[str]) -> Dict[str, bool]:
        """Check multiple tools and return status dict"""
        results = {}
        
        for tool in tools:
            installed = self.check_tool(tool)
            results[tool] = installed
            
            if installed:
                self.logger.info(f"✓ {tool} is installed")
            else:
                self.logger.warning(f"✗ {tool} is NOT installed")
        
        return results
    
    def get_missing_tools(self, tools: List[str]) -> List[str]:
        """Get list of missing tools"""
        return [tool for tool in tools if not self.check_tool(tool)]


class ProgressTracker:
    """Track progress of scanning phases"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.phases = {}
        self.current_phase = None
        self.start_time = None
    
    def start_phase(self, phase_name: str):
        """Start a new phase"""
        self.current_phase = phase_name
        self.start_time = datetime.now()
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"Starting Phase: {phase_name}")
        self.logger.info(f"{'='*60}\n")
    
    def end_phase(self, phase_name: str, results: Optional[Dict] = None):
        """End a phase and log results"""
        if self.start_time:
            duration = (datetime.now() - self.start_time).total_seconds()
            
            self.phases[phase_name] = {
                'duration': duration,
                'results': results or {}
            }
            
            self.logger.info(f"\n{'='*60}")
            self.logger.info(f"Completed Phase: {phase_name}")
            self.logger.info(f"Duration: {duration:.2f} seconds")
            
            if results:
                for key, value in results.items():
                    self.logger.info(f"  {key}: {value}")
            
            self.logger.info(f"{'='*60}\n")
    
    def get_summary(self) -> Dict:
        """Get summary of all phases"""
        total_duration = sum(p['duration'] for p in self.phases.values())
        
        return {
            'phases': self.phases,
            'total_duration': total_duration,
            'phase_count': len(self.phases)
        }


def banner():
    """Print application banner"""
    print(f"""
{Fore.CYAN}{'='*70}
{Fore.GREEN}
    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
    
    Advanced Reconnaissance Automation Framework
    Version 2.0
{Fore.CYAN}{'='*70}
{Style.RESET_ALL}
""")


if __name__ == "__main__":
    # Test utilities
    banner()
    
    # Test logger
    logger = ReconLogger("test", "logs").get_logger()
    logger.debug("Debug message")
    logger.info("Info message")
    logger.warning("Warning message")
    logger.error("Error message")
    
    # Test config loader
    config = ConfigLoader("config/config.yaml")
    print(f"Target: {config.get_target()}")
    print(f"Output: {config.get_output_dir()}")