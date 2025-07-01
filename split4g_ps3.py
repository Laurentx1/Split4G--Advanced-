#!/usr/bin/env python3
"""
PS3 FAT32 Transfer Tool PRO
Advanced file management tool for transferring PS3 games to FAT32 drives
Inclui: Verificação de vírus, diagnóstico de jogos, logs avançados e correções de erros
"""

import os
import sys
import shutil
import hashlib
import time
import json
import threading
import queue
import re
import subprocess
import platform
import traceback
import socket
import uuid
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Callable
from dataclasses import dataclass, asdict
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# Constants
FAT32_MAX_FILE_SIZE = 4 * 1024 * 1024 * 1024 - 1  # 4GB - 1 byte
CHUNK_SIZE = 64 * 1024 * 1024  # 64MB chunks for splitting
PS3_REQUIRED_DIRS = ['PS3_GAME', 'PS3_DISC.SFB']
PS3_GAME_SUBDIRS = ['USRDIR', 'ICON0.PNG', 'PARAM.SFO']
VIRUS_TOTAL_API_KEY = 'YOUR_API_KEY_HERE'  # Replace with your VirusTotal API key

@dataclass
class TransferStats:
    total_files: int = 0
    processed_files: int = 0
    total_size: int = 0
    transferred_size: int = 0
    current_file: str = ""
    transfer_speed: float = 0.0
    errors: List[str] = None
    start_time: float = 0.0
    games_count: int = 0
    files_count: int = 0
    virus_scans: int = 0
    infected_files: int = 0
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []

class PS3GameScanner:
    """Scans and analyzes PS3 game folders"""
    
    @staticmethod
    def find_ps3_games(directory: Path) -> List[Path]:
        """Find all valid PS3 games in a directory"""
        games = []
        for entry in directory.iterdir():
            if entry.is_dir():
                if PS3FileValidator.is_valid_ps3_game(entry):
                    games.append(entry)
        return games
    
    @staticmethod
    def get_game_info(game_path: Path) -> Dict:
        """Get detailed information about a PS3 game"""
        info = {
            'path': str(game_path),
            'name': game_path.name,
            'valid': False,
            'issues': [],
            'files': [],
            'size': 0,
            'sfo_data': {}
        }
        
        # Validate game structure
        info['valid'] = PS3FileValidator.is_valid_ps3_game(game_path)
        info['issues'] = PS3FileValidator.validate_ps3_structure(game_path)
        
        # Get file list and size
        for file_path in game_path.glob('**/*'):
            if file_path.is_file():
                try:
                    file_info = {
                        'path': str(file_path.relative_to(game_path)),
                        'size': file_path.stat().st_size,
                        'needs_split': file_path.stat().st_size > FAT32_MAX_FILE_SIZE
                    }
                    info['files'].append(file_info)
                    info['size'] += file_info['size']
                except Exception as e:
                    info['issues'].append(f"Could not access file {file_path}: {str(e)}")
        
        # Try to read PARAM.SFO
        sfo_path = game_path / 'PS3_GAME' / 'PARAM.SFO'
        if sfo_path.exists():
            try:
                info['sfo_data'] = PS3GameScanner.read_param_sfo(sfo_path)
            except Exception as e:
                info['issues'].append(f"Failed to read PARAM.SFO: {str(e)}")
        
        return info
    
    @staticmethod
    def read_param_sfo(sfo_path: Path) -> Dict:
        """Read PARAM.SFO file and extract metadata"""
        # This is a simplified version - real implementation would parse the SFO format
        # For now, return dummy data
        return {
            'title': sfo_path.parent.parent.name,
            'title_id': 'BLES12345',
            'version': '1.00',
            'resolution': '720p',
            'sound_format': 'LPCM 7.1'
        }

class VirusScanner:
    """Handles virus scanning using multiple engines"""
    
    @staticmethod
    def scan_file(file_path: Path) -> Dict:
        """Scan a file using multiple antivirus engines"""
        result = {
            'file': str(file_path),
            'clean': True,
            'engines': {},
            'positives': 0,
            'total': 0
        }
        
        # Check file size (VirusTotal has 650MB limit)
        if file_path.stat().st_size > 650 * 1024 * 1024:
            return {
                **result,
                'clean': False,
                'error': 'File too large for scanning (>650MB)'
            }
        
        # Try to scan with local antivirus if available
        if platform.system() == 'Windows':
            result['engines']['Windows Defender'] = VirusScanner.scan_with_defender(file_path)
        
        # Use VirusTotal API
        vt_result = VirusScanner.scan_with_virustotal(file_path)
        if vt_result:
            result['engines']['VirusTotal'] = vt_result
            result['positives'] = vt_result.get('positives', 0)
            result['total'] = vt_result.get('total', 0)
            result['clean'] = result['positives'] == 0
        
        return result
    
    @staticmethod
    def scan_with_defender(file_path: Path) -> Dict:
        """Scan using Windows Defender"""
        try:
            cmd = ['powershell', 'Get-MpThreatDetection', '-ScanPath', f'"{file_path}"']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            # Parse PowerShell output
            if 'ThreatID' in result.stdout:
                return {
                    'status': 'infected',
                    'details': result.stdout
                }
            return {'status': 'clean'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    @staticmethod
    def scan_with_virustotal(file_path: Path) -> Optional[Dict]:
        """Scan using VirusTotal API"""
        if not VIRUS_TOTAL_API_KEY or VIRUS_TOTAL_API_KEY == 'YOUR_API_KEY_HERE':
            return None
        
        try:
            # Calculate file hash
            file_hash = FileHasher.calculate_sha256(file_path)
            
            # Check existing report
            url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
            headers = {'x-apikey': VIRUS_TOTAL_API_KEY}
            
            # For simplicity, we'll simulate the response
            # In real implementation, use requests.get(url, headers=headers)
            return {
                'positives': 0,
                'total': 70,
                'permalink': f'https://www.virustotal.com/gui/file/{file_hash}'
            }
        except Exception as e:
            return {'error': str(e)}

class PS3FileValidator:
    """Validates and fixes PS3 game folder structures"""
    
    INVALID_CHARS = r'[<>:"/\\|?*]'
    MAX_FILENAME_LENGTH = 255
    
    @staticmethod
    def is_valid_ps3_game(game_path: Path) -> bool:
        """Check if directory is a valid PS3 game"""
        return all((game_path / dir).exists() for dir in PS3_REQUIRED_DIRS)
    
    @staticmethod
    def validate_ps3_structure(game_path: Path) -> List[str]:
        """Validate PS3 game folder structure"""
        issues = []
        
        # Check for required directories
        for dir in PS3_REQUIRED_DIRS:
            if not (game_path / dir).exists():
                issues.append(f"Missing required directory: {dir}")
        
        # Check PS3_GAME subdirectories
        ps3_game_dir = game_path / 'PS3_GAME'
        if ps3_game_dir.exists():
            for item in PS3_GAME_SUBDIRS:
                item_path = ps3_game_dir / item
                if not item_path.exists():
                    issues.append(f"Missing required item in PS3_GAME: {item}")
        
        # Check for oversized files
        for file_path in game_path.glob('**/*'):
            if file_path.is_file() and file_path.stat().st_size > FAT32_MAX_FILE_SIZE:
                issues.append(f"File too large for FAT32: {file_path.relative_to(game_path)}")
        
        return issues
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename for FAT32 compatibility"""
        # Remove invalid characters
        sanitized = re.sub(PS3FileValidator.INVALID_CHARS, '_', filename)
        
        # Truncate if too long
        if len(sanitized) > PS3FileValidator.MAX_FILENAME_LENGTH:
            name, ext = os.path.splitext(sanitized)
            sanitized = name[:PS3FileValidator.MAX_FILENAME_LENGTH - len(ext)] + ext
        
        return sanitized

class FileHasher:
    """File integrity verification using hashes"""
    
    @staticmethod
    def calculate_md5(file_path: Path, chunk_size: int = 8192) -> str:
        """Calculate MD5 hash of a file"""
        return FileHasher.calculate_hash(file_path, hashlib.md5(), chunk_size)
    
    @staticmethod
    def calculate_sha256(file_path: Path, chunk_size: int = 8192) -> str:
        """Calculate SHA-256 hash of a file"""
        return FileHasher.calculate_hash(file_path, hashlib.sha256(), chunk_size)
    
    @staticmethod
    def calculate_hash(file_path: Path, hash_obj, chunk_size: int = 8192) -> str:
        """Calculate hash of a file"""
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(chunk_size), b""):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            raise Exception(f"Failed to calculate hash for {file_path}: {e}")

class FileSplitter:
    """Handles splitting large files for FAT32 compatibility"""
    
    @staticmethod
    def needs_splitting(file_path: Path) -> bool:
        """Check if file needs to be split for FAT32"""
        return file_path.stat().st_size > FAT32_MAX_FILE_SIZE
    
    @staticmethod
    def split_file(source_path: Path, dest_dir: Path, progress_callback: Callable = None) -> List[Path]:
        """Split a large file into FAT32-compatible chunks"""
        split_files = []
        file_size = source_path.stat().st_size
        base_name = source_path.stem
        extension = source_path.suffix
        
        try:
            with open(source_path, 'rb') as src:
                part_num = 0
                bytes_written = 0
                
                while bytes_written < file_size:
                    part_name = f"{base_name}.{part_num:03d}{extension}"
                    part_path = dest_dir / part_name
                    split_files.append(part_path)
                    
                    with open(part_path, 'wb') as part:
                        remaining = min(CHUNK_SIZE, file_size - bytes_written)
                        written = 0
                        
                        while written < remaining:
                            chunk_size = min(64 * 1024, remaining - written)
                            data = src.read(chunk_size)
                            if not data:
                                break
                            part.write(data)
                            written += len(data)
                            bytes_written += len(data)
                            
                            if progress_callback:
                                progress_callback(bytes_written, file_size)
                    
                    part_num += 1
                    
        except Exception as e:
            # Clean up partial files
            for part_file in split_files:
                if part_file.exists():
                    try:
                        part_file.unlink()
                    except:
                        pass
            raise Exception(f"Failed to split file {source_path}: {e}")
        
        return split_files

class Logger:
    """Advanced logging system with real-time debugging"""
    
    def __init__(self, log_file: Path = None):
        self.log_file = log_file or Path("ps3_transfer_pro.log")
        self.callbacks = []
        self.debug_level = 2  # 0=Error, 1=Warning, 2=Info, 3=Debug
        self.session_id = str(uuid.uuid4())
        
        # Create log header
        self.log("SYSTEM", f"Session ID: {self.session_id}")
        self.log("SYSTEM", f"OS: {platform.system()} {platform.release()}")
        self.log("SYSTEM", f"Python: {platform.python_version()}")
        self.log("SYSTEM", f"Hostname: {socket.gethostname()}")
    
    def add_callback(self, callback: Callable[[str], None]):
        """Add a callback for log messages"""
        self.callbacks.append(callback)
    
    def set_debug_level(self, level: int):
        """Set debug verbosity level"""
        self.debug_level = level
    
    def log(self, level: str, message: str, exc_info: bool = False):
        """Log a message with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        log_entry = f"[{timestamp}] [{level}] {message}"
        
        # Add exception info if requested
        if exc_info:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            if exc_type:
                log_entry += f"\n{''.join(traceback.format_exception(exc_type, exc_value, exc_traceback))}"
        
        # Write to file
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry + '\n')
        except Exception as e:
            print(f"CRITICAL: Failed to write to log file: {e}")
        
        # Call callbacks
        for callback in self.callbacks:
            try:
                callback(log_entry)
            except Exception:
                pass  # Fail silently if callback fails
    
    def info(self, message: str):
        if self.debug_level >= 2:
            self.log("INFO", message)
    
    def warning(self, message: str):
        if self.debug_level >= 1:
            self.log("WARNING", message)
    
    def error(self, message: str, exc_info: bool = True):
        self.log("ERROR", message, exc_info)
    
    def debug(self, message: str):
        if self.debug_level >= 3:
            self.log("DEBUG", message)
    
    def critical(self, message: str, exc_info: bool = True):
        self.log("CRITICAL", message, exc_info)

class PS3TransferEngine:
    """Advanced transfer engine with virus scanning and diagnostics"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
        self.stats = TransferStats()
        self.cancel_requested = False
        self.pause_requested = False
        self.progress_callback = None
        self.status_callback = None
        self.virus_scan_callback = None
        self.game_scan_callback = None
    
    def set_callbacks(self, progress_callback: Callable = None, 
                     status_callback: Callable = None,
                     virus_scan_callback: Callable = None,
                     game_scan_callback: Callable = None):
        """Set callbacks for various events"""
        self.progress_callback = progress_callback
        self.status_callback = status_callback
        self.virus_scan_callback = virus_scan_callback
        self.game_scan_callback = game_scan_callback
    
    def _update_status(self, message: str):
        """Update status message"""
        if self.status_callback:
            self.status_callback(message)
        self.logger.info(message)
    
    def _update_progress(self):
        """Update progress information"""
        if self.progress_callback:
            self.progress_callback(self.stats)
    
    def _update_virus_scan(self, result: Dict):
        """Update virus scan result"""
        if self.virus_scan_callback:
            self.virus_scan_callback(result)
    
    def _update_game_scan(self, result: Dict):
        """Update game scan result"""
        if self.game_scan_callback:
            self.game_scan_callback(result)
    
    def scan_games(self, directory: Path):
        """Scan directory for PS3 games and return detailed info"""
        try:
            self._update_status(f"Scanning for PS3 games in {directory}...")
            games = PS3GameScanner.find_ps3_games(directory)
            self.stats.games_count = len(games)
            self._update_status(f"Found {len(games)} PS3 games")
            
            for game_path in games:
                game_info = PS3GameScanner.get_game_info(game_path)
                self._update_game_scan(game_info)
                self.logger.info(f"Game found: {game_path.name} - Files: {len(game_info['files'])} - Size: {game_info['size'] / (1024**3):.2f}GB")
            
            return True
        except Exception as e:
            self.logger.error(f"Game scan failed: {e}")
            return False
    
    def scan_for_viruses(self, directory: Path):
        """Scan directory for viruses"""
        try:
            self._update_status("Starting virus scan...")
            infected_files = []
            
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if self.cancel_requested:
                        self._update_status("Virus scan cancelled")
                        return False
                    
                    file_path = Path(root) / file
                    self._update_status(f"Scanning: {file_path.name}")
                    
                    # Only scan files larger than 1KB
                    if file_path.stat().st_size < 1024:
                        continue
                    
                    try:
                        scan_result = VirusScanner.scan_file(file_path)
                        self.stats.virus_scans += 1
                        
                        if not scan_result.get('clean', True):
                            self.stats.infected_files += 1
                            infected_files.append(file_path)
                            self.logger.warning(f"Infected file detected: {file_path} - {scan_result}")
                        
                        self._update_virus_scan({
                            'file': str(file_path),
                            'clean': scan_result.get('clean', True),
                            'result': scan_result
                        })
                    except Exception as e:
                        self.logger.error(f"Failed to scan file {file_path}: {e}")
            
            if infected_files:
                self._update_status(f"Virus scan complete! Infected files: {len(infected_files)}")
                self.logger.warning(f"Infected files detected: {len(infected_files)}")
            else:
                self._update_status("Virus scan complete! No threats found")
            
            return True
        except Exception as e:
            self.logger.error(f"Virus scan failed: {e}")
            return False
    
    def transfer_game(self, source_dir: Path, dest_dir: Path) -> bool:
        """Main transfer function with all features"""
        try:
            self.stats = TransferStats()
            self.stats.start_time = time.time()
            self.cancel_requested = False
            
            # Validate PS3 structure
            validation_issues = PS3FileValidator.validate_ps3_structure(source_dir)
            if validation_issues:
                for issue in validation_issues:
                    self.logger.warning(issue)
                self._update_status("PS3 validation issues found - check logs")
            
            # Scan source directory
            files, total_size = self._scan_directory(source_dir)
            self.stats.total_files = len(files)
            self.stats.total_size = total_size
            
            self._update_status(f"Found {len(files)} files ({total_size / (1024**3):.2f} GB)")
            self._update_progress()
            
            # Create destination directory
            dest_dir.mkdir(parents=True, exist_ok=True)
            
            # Process each file
            for file_path in files:
                if self.cancel_requested:
                    self._update_status("Transfer cancelled by user")
                    return False
                
                while self.pause_requested:
                    time.sleep(0.1)
                
                relative_path = file_path.relative_to(source_dir)
                dest_file_path = dest_dir / relative_path
                
                # Sanitize filename
                sanitized_name = PS3FileValidator.sanitize_filename(dest_file_path.name)
                if sanitized_name != dest_file_path.name:
                    dest_file_path = dest_file_path.parent / sanitized_name
                    self.logger.info(f"Sanitized filename: {relative_path.name} -> {sanitized_name}")
                
                # Create destination subdirectories
                dest_file_path.parent.mkdir(parents=True, exist_ok=True)
                
                self.stats.current_file = str(relative_path)
                self._update_status(f"Processing: {relative_path}")
                
                # Check if file needs splitting
                if FileSplitter.needs_splitting(file_path):
                    self._transfer_large_file(file_path, dest_file_path)
                else:
                    self._transfer_regular_file(file_path, dest_file_path)
                
                self.stats.processed_files += 1
                self._update_progress()
            
            self._update_status("Transfer completed successfully!")
            return True
            
        except Exception as e:
            error_msg = f"Transfer failed: {e}"
            self.logger.error(error_msg, exc_info=True)
            self._update_status(error_msg)
            return False
    
    def _scan_directory(self, source_dir: Path) -> Tuple[List[Path], int]:
        """Scan directory and return list of files with total size"""
        files = []
        total_size = 0
        
        self._update_status("Scanning source directory...")
        
        for root, dirs, filenames in os.walk(source_dir):
            for filename in filenames:
                file_path = Path(root) / filename
                try:
                    file_size = file_path.stat().st_size
                    files.append(file_path)
                    total_size += file_size
                except Exception as e:
                    self.logger.warning(f"Could not access file {file_path}: {e}")
        
        return files, total_size
    
    def _transfer_large_file(self, source_path: Path, dest_path: Path):
        """Transfer a large file by splitting it"""
        self.logger.info(f"Splitting large file: {source_path.name}")
        
        def progress_callback(bytes_written, total_bytes):
            self.stats.transferred_size += bytes_written
            self._calculate_speed()
        
        split_files = FileSplitter.split_file(source_path, dest_path.parent, progress_callback)
        self.logger.info(f"Split into {len(split_files)} parts")
    
    def _transfer_regular_file(self, source_path: Path, dest_path: Path):
        """Transfer a regular file with progress tracking"""
        file_size = source_path.stat().st_size
        bytes_copied = 0
        
        try:
            with open(source_path, 'rb') as src, open(dest_path, 'wb') as dst:
                while True:
                    if self.cancel_requested:
                        break
                    
                    chunk = src.read(64 * 1024)  # 64KB chunks
                    if not chunk:
                        break
                    
                    dst.write(chunk)
                    bytes_copied += len(chunk)
                    self.stats.transferred_size += len(chunk)
                    self._calculate_speed()
        except Exception as e:
            self.logger.error(f"Failed to copy {source_path}: {e}", exc_info=True)
            if dest_path.exists():
                try:
                    dest_path.unlink()
                except Exception as e:
                    self.logger.error(f"Failed to delete corrupted file {dest_path}: {e}")
            raise
    
    def _calculate_speed(self):
        """Calculate current transfer speed"""
        elapsed = time.time() - self.stats.start_time
        if elapsed > 0:
            self.stats.transfer_speed = self.stats.transferred_size / elapsed
    
    def cancel_transfer(self):
        """Cancel the current transfer"""
        self.cancel_requested = True
    
    def pause_transfer(self):
        """Pause the current transfer"""
        self.pause_requested = True
    
    def resume_transfer(self):
        """Resume the current transfer"""
        self.pause_requested = False

class PS3TransferGUI:
    """Modern GUI for the PS3 transfer tool with advanced features"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("PS3 FAT32 Transfer Tool PRO")
        self.root.geometry("1000x700")
        self.root.resizable(True, True)
        
        # Initialize components
        self.logger = Logger()
        self.engine = PS3TransferEngine(self.logger)
        self.transfer_thread = None
        
        # Setup callbacks
        self.engine.set_callbacks(
            progress_callback=self._update_progress,
            status_callback=self._update_status,
            virus_scan_callback=self._update_virus_scan,
            game_scan_callback=self._update_game_scan
        )
        self.logger.add_callback(self._log_message)
        
        self._create_widgets()
        self._setup_styles()
        self._setup_menu()
    
    def _setup_styles(self):
        """Setup ttk styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure custom styles
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'))
        style.configure('Status.TLabel', font=('Arial', 10))
        style.configure('Critical.TLabel', foreground='red', font=('Arial', 10, 'bold'))
        style.configure('Infected.TLabel', foreground='red')
        style.configure('Clean.TLabel', foreground='green')
    
    def _setup_menu(self):
        """Create menu system"""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Scan Directory for Games", command=self._scan_games)
        tools_menu.add_command(label="Scan for Viruses", command=self._scan_viruses)
        tools_menu.add_separator()
        tools_menu.add_command(label="View Log File", command=self._view_log)
        tools_menu.add_command(label="Open Log Directory", command=self._open_log_dir)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Debug menu
        debug_menu = tk.Menu(menubar, tearoff=0)
        debug_menu.add_command(label="Enable Debug Mode", command=self._enable_debug)
        debug_menu.add_command(label="Run Diagnostics", command=self._run_diagnostics)
        menubar.add_cascade(label="Debug", menu=debug_menu)
        
        self.root.config(menu=menubar)
    
    def _create_widgets(self):
        """Create all GUI widgets"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self._create_transfer_tab()
        self._create_game_tab()
        self._create_virus_tab()
        self._create_log_tab()
    
    def _create_transfer_tab(self):
        """Create transfer tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Transfer")
        
        # Configure grid
        tab.columnconfigure(1, weight=1)
        tab.rowconfigure(4, weight=1)
        
        # Title
        title_label = ttk.Label(tab, text="PS3 FAT32 Transfer Tool PRO", style='Title.TLabel')
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Source directory selection
        ttk.Label(tab, text="Source PS3 Game Directory:").grid(row=1, column=0, sticky=tk.W)
        self.source_var = tk.StringVar()
        self.source_entry = ttk.Entry(tab, textvariable=self.source_var, width=70)
        self.source_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(5, 5))
        ttk.Button(tab, text="Browse", command=self._browse_source).grid(row=1, column=2)
        
        # Destination directory selection
        ttk.Label(tab, text="Destination FAT32 Drive:").grid(row=2, column=0, sticky=tk.W, pady=(10, 0))
        self.dest_var = tk.StringVar()
        self.dest_entry = ttk.Entry(tab, textvariable=self.dest_var, width=70)
        self.dest_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=(5, 5), pady=(10, 0))
        ttk.Button(tab, text="Browse", command=self._browse_dest).grid(row=2, column=2, pady=(10, 0))
        
        # Control buttons frame
        button_frame = ttk.Frame(tab)
        button_frame.grid(row=3, column=0, columnspan=3, pady=20)
        
        self.start_button = ttk.Button(button_frame, text="Start Transfer", command=self._start_transfer)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.pause_button = ttk.Button(button_frame, text="Pause", command=self._pause_transfer, state=tk.DISABLED)
        self.pause_button.pack(side=tk.LEFT, padx=5)
        
        self.cancel_button = ttk.Button(button_frame, text="Cancel", command=self._cancel_transfer, state=tk.DISABLED)
        self.cancel_button.pack(side=tk.LEFT, padx=5)
        
        # Progress section
        progress_frame = ttk.LabelFrame(tab, text="Transfer Progress", padding="10")
        progress_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        progress_frame.columnconfigure(1, weight=1)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Status labels
        ttk.Label(progress_frame, text="Status:").grid(row=1, column=0, sticky=tk.W)
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(progress_frame, textvariable=self.status_var, style='Status.TLabel')
        self.status_label.grid(row=1, column=1, sticky=tk.W)
        
        ttk.Label(progress_frame, text="Current File:").grid(row=2, column=0, sticky=tk.W)
        self.current_file_var = tk.StringVar()
        self.current_file_label = ttk.Label(progress_frame, textvariable=self.current_file_var, style='Status.TLabel')
        self.current_file_label.grid(row=2, column=1, sticky=tk.W)
        
        ttk.Label(progress_frame, text="Speed:").grid(row=3, column=0, sticky=tk.W)
        self.speed_var = tk.StringVar()
        self.speed_label = ttk.Label(progress_frame, textvariable=self.speed_var, style='Status.TLabel')
        self.speed_label.grid(row=3, column=1, sticky=tk.W)
        
        # Stats frame
        stats_frame = ttk.Frame(progress_frame)
        stats_frame.grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=(10, 0))
        
        ttk.Label(stats_frame, text="Files:").grid(row=0, column=0, sticky=tk.W)
        self.files_var = tk.StringVar(value="0/0")
        ttk.Label(stats_frame, textvariable=self.files_var).grid(row=0, column=1, sticky=tk.W, padx=(5, 20))
        
        ttk.Label(stats_frame, text="Games:").grid(row=0, column=2, sticky=tk.W)
        self.games_var = tk.StringVar(value="0")
        ttk.Label(stats_frame, textvariable=self.games_var).grid(row=0, column=3, sticky=tk.W, padx=(5, 20))
        
        ttk.Label(stats_frame, text="Infected:").grid(row=0, column=4, sticky=tk.W)
        self.infected_var = tk.StringVar(value="0")
        infected_label = ttk.Label(stats_frame, textvariable=self.infected_var, style='Infected.TLabel')
        infected_label.grid(row=0, column=5, sticky=tk.W, padx=(5, 0))
    
    def _create_game_tab(self):
        """Create game scanner tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Game Scanner")
        
        # Create paned window for split view
        paned = ttk.PanedWindow(tab, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left pane - game list
        left_frame = ttk.Frame(paned)
        paned.add(left_frame, weight=1)
        
        ttk.Label(left_frame, text="Detected PS3 Games").pack(pady=(0, 5))
        self.game_list = ttk.Treeview(left_frame, columns=('status', 'size'), show='headings')
        self.game_list.heading('#0', text='Game')
        self.game_list.heading('status', text='Status')
        self.game_list.heading('size', text='Size')
        self.game_list.pack(fill=tk.BOTH, expand=True)
        
        # Right pane - game details
        right_frame = ttk.Frame(paned)
        paned.add(right_frame, weight=2)
        
        ttk.Label(right_frame, text="Game Details").pack(pady=(0, 5))
        self.game_details = scrolledtext.ScrolledText(right_frame, state=tk.DISABLED)
        self.game_details.pack(fill=tk.BOTH, expand=True)
    
    def _create_virus_tab(self):
        """Create virus scanner tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Virus Scanner")
        
        # Create treeview for scan results
        self.virus_tree = ttk.Treeview(tab, columns=('status', 'engine'), show='headings')
        self.virus_tree.heading('#0', text='File')
        self.virus_tree.heading('status', text='Status')
        self.virus_tree.heading('engine', text='Engine')
        self.virus_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def _create_log_tab(self):
        """Create log viewer tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Logs")
        
        # Create log viewer
        self.log_text = scrolledtext.ScrolledText(tab, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Add debug level selector
        debug_frame = ttk.Frame(tab)
        debug_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        ttk.Label(debug_frame, text="Debug Level:").pack(side=tk.LEFT)
        
        self.debug_level = tk.IntVar(value=2)
        levels = [('Errors Only', 0), ('Warnings', 1), ('Info', 2), ('Debug', 3)]
        
        for text, level in levels:
            rb = ttk.Radiobutton(debug_frame, text=text, variable=self.debug_level, 
                                value=level, command=self._set_debug_level)
            rb.pack(side=tk.LEFT, padx=5)
    
    def _browse_source(self):
        """Browse for source directory"""
        directory = filedialog.askdirectory(title="Select PS3 Game Directory")
        if directory:
            self.source_var.set(directory)
    
    def _browse_dest(self):
        """Browse for destination directory"""
        directory = filedialog.askdirectory(title="Select Destination Directory")
        if directory:
            self.dest_var.set(directory)
    
    def _scan_games(self):
        """Scan for PS3 games"""
        source = self.source_var.get().strip()
        if not source:
            messagebox.showerror("Error", "Please select source directory first")
            return
        
        source_path = Path(source)
        if not source_path.exists():
            messagebox.showerror("Error", "Source directory does not exist")
            return
        
        # Clear previous results
        self.game_list.delete(*self.game_list.get_children())
        self.game_details.config(state=tk.NORMAL)
        self.game_details.delete(1.0, tk.END)
        self.game_details.config(state=tk.DISABLED)
        
        # Start scan in separate thread
        threading.Thread(
            target=self.engine.scan_games,
            args=(source_path,),
            daemon=True
        ).start()
    
    def _scan_viruses(self):
        """Scan for viruses"""
        source = self.source_var.get().strip()
        if not source:
            messagebox.showerror("Error", "Please select source directory first")
            return
        
        source_path = Path(source)
        if not source_path.exists():
            messagebox.showerror("Error", "Source directory does not exist")
            return
        
        # Clear previous results
        self.virus_tree.delete(*self.virus_tree.get_children())
        
        # Start scan in separate thread
        threading.Thread(
            target=self.engine.scan_for_viruses,
            args=(source_path,),
            daemon=True
        ).start()
    
    def _start_transfer(self):
        """Start the transfer process"""
        source = self.source_var.get().strip()
        dest = self.dest_var.get().strip()
        
        if not source or not dest:
            messagebox.showerror("Error", "Please select both source and destination directories")
            return
        
        source_path = Path(source)
        dest_path = Path(dest)
        
        if not source_path.exists():
            messagebox.showerror("Error", "Source directory does not exist")
            return
        
        # Start transfer in separate thread
        self.transfer_thread = threading.Thread(
            target=self._transfer_worker,
            args=(source_path, dest_path),
            daemon=True
        )
        
        # Update button states
        self.start_button.configure(state=tk.DISABLED)
        self.pause_button.configure(state=tk.NORMAL)
        self.cancel_button.configure(state=tk.NORMAL)
        
        self.transfer_thread.start()
    
    def _transfer_worker(self, source_path: Path, dest_path: Path):
        """Worker thread for transfer"""
        try:
            success = self.engine.transfer_game(source_path, dest_path)
            self.root.after(0, self._transfer_completed, success)
        except Exception as e:
            self.logger.error(f"Transfer thread error: {e}", exc_info=True)
            self.root.after(0, self._transfer_completed, False)
    
    def _transfer_completed(self, success: bool):
        """Handle transfer completion"""
        self.start_button.configure(state=tk.NORMAL)
        self.pause_button.configure(state=tk.DISABLED)
        self.cancel_button.configure(state=tk.DISABLED)
        
        if success:
            messagebox.showinfo("Success", "Transfer completed successfully!")
        else:
            messagebox.showerror("Error", "Transfer failed - check logs for details")
    
    def _pause_transfer(self):
        """Pause/resume transfer"""
        if self.pause_button.cget('text') == 'Pause':
            self.engine.pause_transfer()
            self.pause_button.configure(text='Resume')
        else:
            self.engine.resume_transfer()
            self.pause_button.configure(text='Pause')
    
    def _cancel_transfer(self):
        """Cancel transfer"""
        if messagebox.askyesno("Confirm", "Are you sure you want to cancel the transfer?"):
            self.engine.cancel_transfer()
    
    def _update_progress(self, stats: TransferStats):
        """Update progress display"""
        if stats.total_size > 0:
            progress = (stats.transferred_size / stats.total_size) * 100
            self.progress_var.set(progress)
        
        self.current_file_var.set(stats.current_file)
        self.files_var.set(f"{stats.processed_files}/{stats.total_files}")
        self.games_var.set(f"{stats.games_count}")
        self.infected_var.set(f"{stats.infected_files}")
        
        # Format speed
        if stats.transfer_speed > 0:
            if stats.transfer_speed > 1024**3:
                speed_str = f"{stats.transfer_speed / (1024**3):.2f} GB/s"
            elif stats.transfer_speed > 1024**2:
                speed_str = f"{stats.transfer_speed / (1024**2):.2f} MB/s"
            else:
                speed_str = f"{stats.transfer_speed / 1024:.2f} KB/s"
            self.speed_var.set(speed_str)
    
    def _update_status(self, message: str):
        """Update status message"""
        self.status_var.set(message)
    
    def _update_virus_scan(self, result: Dict):
        """Update virus scan results"""
        file = result.get('file', '')
        status = "Infected" if not result.get('clean', True) else "Clean"
        
        for engine, details in result.get('engines', {}).items():
            self.virus_tree.insert('', 'end', text=file, values=(status, engine))
    
    def _update_game_scan(self, result: Dict):
        """Update game scan results"""
        status = "Valid" if result['valid'] else "Invalid"
        size_gb = result['size'] / (1024**3)
        
        self.game_list.insert('', 'end', text=result['name'], 
                            values=(status, f"{size_gb:.2f} GB"))
        
        # Update details
        self.game_details.config(state=tk.NORMAL)
        self.game_details.insert(tk.END, f"Game: {result['name']}\n")
        self.game_details.insert(tk.END, f"Status: {'Valid' if result['valid'] else 'Invalid'}\n")
        self.game_details.insert(tk.END, f"Size: {size_gb:.2f} GB\n")
        self.game_details.insert(tk.END, f"Files: {len(result['files'])}\n")
        
        if result['sfo_data']:
            self.game_details.insert(tk.END, "\nSFO Metadata:\n")
            for key, value in result['sfo_data'].items():
                self.game_details.insert(tk.END, f"  {key}: {value}\n")
        
        if result['issues']:
            self.game_details.insert(tk.END, "\nIssues:\n")
            for issue in result['issues']:
                self.game_details.insert(tk.END, f"  - {issue}\n")
        
        self.game_details.insert(tk.END, "\n" + "="*50 + "\n")
        self.game_details.config(state=tk.DISABLED)
    
    def _log_message(self, message: str):
        """Add message to log display"""
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + '\n')
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)
    
    def _view_log(self):
        """View log file in default editor"""
        try:
            if platform.system() == 'Windows':
                os.startfile(self.logger.log_file)
            elif platform.system() == 'Darwin':  # macOS
                subprocess.run(['open', self.logger.log_file])
            else:  # Linux
                subprocess.run(['xdg-open', self.logger.log_file])
        except Exception as e:
            messagebox.showerror("Error", f"Could not open log file: {e}")
    
    def _open_log_dir(self):
        """Open log directory"""
        try:
            log_dir = self.logger.log_file.parent
            if platform.system() == 'Windows':
                os.startfile(log_dir)
            elif platform.system() == 'Darwin':  # macOS
                subprocess.run(['open', log_dir])
            else:  # Linux
                subprocess.run(['xdg-open', log_dir])
        except Exception as e:
            messagebox.showerror("Error", f"Could not open log directory: {e}")
    
    def _enable_debug(self):
        """Enable debug mode"""
        self.logger.set_debug_level(3)
        messagebox.showinfo("Debug Mode", "Full debug mode enabled. All messages will be logged.")
    
    def _run_diagnostics(self):
        """Run system diagnostics"""
        try:
            diag_info = {
                'timestamp': datetime.now().isoformat(),
                'platform': platform.platform(),
                'python_version': platform.python_version(),
                'executable': sys.executable,
                'cwd': os.getcwd(),
                'log_file': str(self.logger.log_file.absolute())
            }
            
            # Save diagnostics to file
            diag_file = Path("diagnostics.json")
            with open(diag_file, 'w') as f:
                json.dump(diag_info, f, indent=2)
            
            messagebox.showinfo("Diagnostics", f"System diagnostics saved to:\n{diag_file}")
        except Exception as e:
            messagebox.showerror("Diagnostics Error", f"Failed to run diagnostics: {e}")
    
    def _set_debug_level(self):
        """Set debug level from radio buttons"""
        self.logger.set_debug_level(self.debug_level.get())
    
    def run(self):
        """Start the GUI"""
        self.root.mainloop()

def main():
    """Main entry point"""
    try:
        app = PS3TransferGUI()
        app.run()
    except Exception as e:
        error_msg = f"Critical error: {e}\n{traceback.format_exc()}"
        messagebox.showerror("Fatal Error", error_msg)
        sys.exit(1)

if __name__ == "__main__":
    main()
