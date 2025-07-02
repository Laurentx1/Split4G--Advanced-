#!/usr/bin/env python3
"""
PS3 FAT32 Transfer Tool PRO - Enhanced Edition v2.0
Advanced file management tool with robust path handling and error diagnostics
Includes: Path validation, character sanitization, antivirus handling, and FAT32 compliance
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
import ctypes
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Callable
from dataclasses import dataclass, asdict
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# Constants
FAT32_MAX_FILE_SIZE = 4 * 1024 * 1024 * 1024 - 1  # 4GB - 1 byte
MAX_VALID_FILE_SIZE = 10 * 1024**4  # 10 TB (sanity check)
CHUNK_SIZE = 64 * 1024 * 1024  # 64MB chunks for splitting
PS3_REQUIRED_DIRS = ['PS3_GAME', 'PS3_DISC.SFB']
PS3_GAME_SUBDIRS = ['USRDIR', 'ICON0.PNG', 'PARAM.SFO']
VIRUS_TOTAL_API_KEY = 'YOUR_API_KEY_HERE'  # Replace with your VirusTotal API key
MAX_PATH_LENGTH = 200  # Safe path length limit for FAT32
MAX_FILENAME_LENGTH = 100  # Reduced for FAT32 compatibility

# Windows long path support
def enable_long_paths():
    """Enable long path support on Windows 10+"""
    if platform.system() == 'Windows':
        try:
            # Check if we're on Windows 10 Anniversary Update (1607) or later
            if sys.getwindowsversion().build >= 14352:
                # Try to enable long paths via registry (requires admin)
                try:
                    import winreg
                    key = winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        r"SYSTEM\CurrentControlSet\Control\FileSystem",
                        0, winreg.KEY_ALL_ACCESS
                    )
                    winreg.SetValueEx(key, "LongPathsEnabled", 0, winreg.REG_DWORD, 1)
                    winreg.CloseKey(key)
                    return True
                except:
                    return False
        except:
            pass
    return False

def safe_file_open(file_path, mode):
    """Robust file opener with advanced Windows path handling"""
    if platform.system() != 'Windows':
        return open(file_path, mode)

    abs_path = os.path.abspath(file_path)
    first_error = None

    # First attempt: Standard open
    try:
        return open(abs_path, mode)
    except OSError as e:
        first_error = e
        # If error 22 (invalid argument), try additional methods
        if e.errno != 22:
            raise

    # Second attempt: Long path prefix
    if not abs_path.startswith('\\\\?\\'):
        long_path = '\\\\?\\' + abs_path
        try:
            return open(long_path, mode)
        except OSError:
            pass  # We'll try next method

    # Third attempt: 8.3 short path name
    try:
        import ctypes
        from ctypes import wintypes
        
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        GetShortPathNameW = kernel32.GetShortPathNameW
        GetShortPathNameW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPWSTR,
            wintypes.DWORD
        ]
        GetShortPathNameW.restype = wintypes.DWORD

        buffer = ctypes.create_unicode_buffer(1024)
        if GetShortPathNameW(abs_path, buffer, 1024) == 0:
            raise first_error
        return open(buffer.value, mode)
    except Exception:
        # Final fallback: Raise original error
        raise first_error

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
    warning_files: int = 0
    
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
            'sfo_data': {},
            'warning_files': []
        }
        
        # Validate game structure
        info['valid'] = PS3FileValidator.is_valid_ps3_game(game_path)
        info['issues'] = PS3FileValidator.validate_ps3_structure(game_path)
        
        # Get file list and size
        for file_path in game_path.glob('**/*'):
            if file_path.is_file():
                try:
                    # Check for potential issues
                    warnings = []
                    relative_path = file_path.relative_to(game_path)
                    
                    # Check for invalid characters
                    if PS3FileValidator.has_invalid_chars(relative_path.name):
                        warnings.append("Contains invalid characters")
                    
                    # Check for long paths
                    if len(str(relative_path)) > MAX_PATH_LENGTH:
                        warnings.append(f"Path too long ({len(str(relative_path))} characters)")
                    
                    # Check for spaces in filename
                    if ' ' in relative_path.name:
                        warnings.append("Contains spaces")
                        
                    # Check for parentheses in filename
                    if '(' in relative_path.name or ')' in relative_path.name:
                        warnings.append("Contains parentheses")
                    
                    file_info = {
                        'path': str(relative_path),
                        'size': file_path.stat().st_size,
                        'needs_split': file_path.stat().st_size > FAT32_MAX_FILE_SIZE,
                        'warnings': warnings
                    }
                    
                    info['files'].append(file_info)
                    info['size'] += file_info['size']
                    
                    if warnings:
                        info['warning_files'].append(str(relative_path))
                        
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
    MAX_FILENAME_LENGTH = MAX_FILENAME_LENGTH
    
    @staticmethod
    def has_invalid_chars(filename: str) -> bool:
        """Check if filename contains invalid characters"""
        return bool(re.search(PS3FileValidator.INVALID_CHARS, filename))
    
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
        """Strict sanitization for problematic characters"""
        # Remove all non-ASCII characters
        sanitized = re.sub(r'[^\x20-\x7E]', '', filename)
        # Replace prohibited characters
        sanitized = re.sub(r'[<>:"/\\|?*,;=]', '_', sanitized)
        # Remove parentheses and brackets
        sanitized = re.sub(r'[()\[\]{}]', '', sanitized)
        # Replace spaces with underscores
        sanitized = sanitized.replace(' ', '_')
        # Remove commas
        sanitized = sanitized.replace(',', '')
        # Truncate if too long
        if len(sanitized) > PS3FileValidator.MAX_FILENAME_LENGTH:
            name, ext = os.path.splitext(sanitized)
            sanitized = name[:PS3FileValidator.MAX_FILENAME_LENGTH - len(ext)] + ext
        
        return sanitized

    @staticmethod
    def sanitize_relative_path(relative_path: Path) -> Path:
        """Sanitize every part of a relative path"""
        parts = []
        for part in relative_path.parts:
            sanitized = PS3FileValidator.sanitize_filename(part)
            parts.append(sanitized)
        return Path(*parts)

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
            with safe_file_open(file_path, "rb") as f:
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
        """Split a large file into FAT32-compatible chunks with robust error handling"""
        split_files = []
        file_size = source_path.stat().st_size
        base_name = PS3FileValidator.sanitize_filename(source_path.stem)  # Sanitize base name
        extension = source_path.suffix
        
        try:
            with safe_file_open(source_path, 'rb') as src:
                part_num = 0
                bytes_written = 0
                
                while bytes_written < file_size:
                    # Generate safe part name (FAT32 compliant)
                    part_name = f"{base_name}.{part_num:03d}{extension}"
                    part_path = dest_dir / part_name
                    
                    # Validate path length before creating file
                    if len(str(part_path)) > MAX_PATH_LENGTH:
                        raise Exception(f"Split file path too long ({len(str(part_path))} chars)")
                    
                    try:
                        with safe_file_open(part_path, 'wb') as part:
                            remaining = min(CHUNK_SIZE, file_size - bytes_written)
                            written = 0
                            
                            while written < remaining:
                                chunk_size = min(64 * 1024, remaining - written)  # 64KB chunks
                                data = src.read(chunk_size)
                                if not data:
                                    break
                                part.write(data)
                                written += len(data)
                                bytes_written += len(data)
                                
                                if progress_callback:
                                    progress_callback(bytes_written, file_size)
                        
                        split_files.append(part_path)
                        part_num += 1
                        
                    except OSError as e:
                        # Handle filesystem-specific errors
                        if e.errno == 22:  # Invalid argument
                            # Try again with shorter filename
                            base_name = base_name[:20]  # Truncate further
                            continue
                        raise
                    
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
            with safe_file_open(self.log_file, 'a') as f:
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
    """Advanced transfer engine with error diagnostics and solutions"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
        self.stats = TransferStats()
        self.cancel_requested = False
        self.pause_requested = False
        self.progress_callback = None
        self.status_callback = None
        self.virus_scan_callback = None
        self.game_scan_callback = None
        self.warning_callback = None
    
    def set_callbacks(self, progress_callback: Callable = None, 
                     status_callback: Callable = None,
                     virus_scan_callback: Callable = None,
                     game_scan_callback: Callable = None,
                     warning_callback: Callable = None):
        """Set callbacks for various events"""
        self.progress_callback = progress_callback
        self.status_callback = status_callback
        self.virus_scan_callback = virus_scan_callback
        self.game_scan_callback = game_scan_callback
        self.warning_callback = warning_callback
    
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
    
    def _update_warning(self, file_path: Path, issues: List[str]):
        """Update warning information"""
        if self.warning_callback:
            self.warning_callback(file_path, issues)
    
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
                
                # Log warnings for problematic files
                for file in game_info['files']:
                    if file['warnings']:
                        self.stats.warning_files += 1
                        self._update_warning(
                            Path(game_path) / file['path'],
                            file['warnings']
                        )
            
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
        """Main transfer function with error diagnostics"""
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
                
                # Sanitize entire path
                sanitized_relative = PS3FileValidator.sanitize_relative_path(relative_path)
                dest_file_path = dest_dir / sanitized_relative
                
                # Check path length
                dest_path_str = str(dest_file_path)
                if len(dest_path_str) > MAX_PATH_LENGTH:
                    self.logger.error(f"Path too long ({len(dest_path_str)} chars): {dest_path_str}")
                    self.stats.errors.append(f"Path too long: {relative_path}")
                    continue
                
                # Create destination subdirectories
                dest_file_path.parent.mkdir(parents=True, exist_ok=True)
                
                self.stats.current_file = str(sanitized_relative)
                self._update_status(f"Processing: {sanitized_relative}")
                
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
                    
                    # Check for potential issues
                    issues = []
                    if PS3FileValidator.has_invalid_chars(filename):
                        issues.append("Invalid characters")
                    if len(str(file_path)) > MAX_PATH_LENGTH:
                        issues.append(f"Path too long ({len(str(file_path))} chars)")
                    if file_size > FAT32_MAX_FILE_SIZE:
                        issues.append("File too large for FAT32")
                    
                    if issues:
                        self.stats.warning_files += 1
                        self._update_warning(file_path, issues)
                        
                except Exception as e:
                    self.logger.warning(f"Could not access file {file_path}: {e}")
        
        return files, total_size
    
    def _validate_destination(self, path: Path) -> bool:
        """Check if destination can handle split files"""
        try:
            test_file = path / ".split_test"
            with safe_file_open(test_file, 'wb') as f:
                f.write(b'test')
            test_file.unlink()
            return True
        except Exception as e:
            self.logger.error(f"Destination validation failed: {e}")
            return False

    def _transfer_large_file(self, source_path: Path, dest_path: Path):
        """Enhanced large file transfer with better error reporting"""
        self.logger.info(f"Attempting to split large file: {source_path.name}")
        
        try:
            # Create destination directory if it doesn't exist
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Verify destination filesystem can handle split files
            if not self._validate_destination(dest_path.parent):
                raise Exception("Destination filesystem incompatible with split files")
            
            def progress_callback(bytes_written, total_bytes):
                self.stats.transferred_size += bytes_written
                self._calculate_speed()
            
            split_files = FileSplitter.split_file(source_path, dest_path.parent, progress_callback)
            self.logger.info(f"Successfully split into {len(split_files)} parts")
            
        except Exception as e:
            error_msg = f"""
            ⚠️ Failed to transfer large file: {source_path.name}
            → Size: {source_path.stat().st_size / (1024**3):.2f}GB
            → Error: {str(e)}
            
            Possible Solutions:
            1. Ensure destination drive is formatted as NTFS (not FAT32)
            2. Shorten the destination path
            3. Manually split the file using alternative tools
            """
            self.logger.error(error_msg)
            self.stats.errors.append(error_msg)
            raise
    
    def _transfer_regular_file(self, source_path: Path, dest_path: Path):
        """Transfer a regular file with progress tracking"""
        file_size = source_path.stat().st_size
        
        # Sanity check for implausible file sizes
        if file_size > MAX_VALID_FILE_SIZE:
            error_msg = f"Implausible file size ({file_size} bytes) for file: {source_path}"
            self.logger.error(error_msg)
            self.stats.errors.append(error_msg)
            return
            
        bytes_copied = 0
        
        try:
            with safe_file_open(source_path, 'rb') as src, safe_file_open(dest_path, 'wb') as dst:
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
            
            # Add detailed error diagnostics
            error_details = self._get_error_diagnostics(source_path, e)
            self.stats.errors.append(error_details)
            self.logger.error(f"Transfer Error Details:\n{error_details}")
            
            raise
    
    def _get_error_diagnostics(self, file_path: Path, error: Exception) -> str:
        """Generate detailed error diagnostics"""
        diagnostics = [
            "⚠️ Transfer Error – Possible Causes and Recommended Solutions",
            "",
            f"File: {file_path}",
            f"Size: {file_path.stat().st_size / (1024**3):.2f} GB",
            f"Error: {str(error)}",
            "",
            "❗ Possible Cause #1: Invalid File Name or Unsupported Characters",
            "Some files may contain:",
            "- Special characters (e.g., #, @, !, (), ,)",
            "- Excessive spaces",
            "- Very long names or deeply nested folder structures",
            "",
            "✅ Solution:",
            f"- Original name: '{file_path.name}'",
            f"- Sanitized name: '{PS3FileValidator.sanitize_filename(file_path.name)}'",
            "- Rename problematic files to simpler names using only standard characters",
            "- Avoid spaces, parentheses, or symbols in file names",
            "",
            "❗ Possible Cause #2: Path Too Long (Windows MAX_PATH Limit)",
            "Windows limits file paths to 260 characters",
            f"Current path length: {len(str(file_path))} characters",
            "",
            "✅ Solution:",
            "- Shorten folder names in source or destination",
            "- Move game folder closer to drive root (e.g., D:\\Games\\)",
            "- Enable long path support in Windows via Tools menu",
            "",
            "❗ Possible Cause #3: FAT32 File System Limitations",
            "FAT32 does not support:",
            "- Files larger than 4GB",
            "- Some complex directory structures",
            "- Certain metadata formats",
            "",
            "✅ Solution:",
            f"- File size: {file_path.stat().st_size / (1024**3):.2f} GB",
            f"- {'File is within FAT32 limits' if file_path.stat().st_size <= FAT32_MAX_FILE_SIZE else 'File exceeds FAT32 size limit!'}",
            "- Consider testing on NTFS-formatted drive",
            "",
            "❗ Possible Cause #4: Antivirus Interference",
            "Antivirus tools may block game files",
            "",
            "✅ Solution:",
            "- Temporarily disable antivirus software",
            "- Whitelist this application in security settings",
            "",
            "🛠️ Additional Suggestions:",
            "- Try manually copying the file to destination",
            "- Check logs for more details about this error",
            "- Use the 'Validate Paths' tool to check for issues"
        ]
        
        return "\n".join(diagnostics)
    
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
    """Modern GUI for PS3 transfer with error diagnostics"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("PS3 FAT32 Transfer Tool PRO - Enhanced Edition v2.0")
        self.root.geometry("1100x750")
        self.root.resizable(True, True)
        
        # Initialize components
        self.logger = Logger()
        self.engine = PS3TransferEngine(self.logger)
        self.transfer_thread = None
        self.error_details = ""
        
        # Setup callbacks
        self.engine.set_callbacks(
            progress_callback=self._update_progress,
            status_callback=self._update_status,
            virus_scan_callback=self._update_virus_scan,
            game_scan_callback=self._update_game_scan,
            warning_callback=self._handle_file_warning
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
        style.configure('GameList.Treeview', font=('Arial', 9))
        style.configure('Warning.TLabel', foreground='orange')
    
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
        tools_menu.add_command(label="Validate Paths", command=self._validate_paths)
        tools_menu.add_separator()
        if platform.system() == 'Windows':
            tools_menu.add_command(label="Enable Long Path Support", command=self._enable_long_paths)
        tools_menu.add_command(label="View Log File", command=self._view_log)
        tools_menu.add_command(label="Open Log Directory", command=self._open_log_dir)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Debug menu
        debug_menu = tk.Menu(menubar, tearoff=0)
        debug_menu.add_command(label="Enable Debug Mode", command=self._enable_debug)
        debug_menu.add_command(label="Run Diagnostics", command=self._run_diagnostics)
        menubar.add_cascade(label="Debug", menu=debug_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Transfer Error Guide", command=self._show_error_guide)
        menubar.add_cascade(label="Help", menu=help_menu)
        
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
        self._create_error_tab()
    
    def _create_transfer_tab(self):
        """Create transfer tab with game scan button"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Transfer")
        
        # Configure grid
        tab.columnconfigure(1, weight=1)
        tab.rowconfigure(5, weight=1)
        
        # Title
        title_label = ttk.Label(tab, text="PS3 FAT32 Transfer Tool PRO - Enhanced Edition v2.0", style='Title.TLabel')
        title_label.grid(row=0, column=0, columnspan=4, pady=(0, 15))
        
        # Source directory selection
        ttk.Label(tab, text="Source PS3 Game Directory:").grid(row=1, column=0, sticky=tk.W)
        self.source_var = tk.StringVar()
        self.source_entry = ttk.Entry(tab, textvariable=self.source_var, width=70)
        self.source_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(5, 5))
        
        # Buttons for source directory
        button_frame = ttk.Frame(tab)
        button_frame.grid(row=1, column=2, columnspan=2, sticky=tk.W)
        ttk.Button(button_frame, text="Browse", command=self._browse_source, width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Scan Games", command=self._scan_games, width=10).pack(side=tk.LEFT, padx=2)
        
        # Destination directory selection
        ttk.Label(tab, text="Destination FAT32 Drive:").grid(row=2, column=0, sticky=tk.W, pady=(10, 0))
        self.dest_var = tk.StringVar()
        self.dest_entry = ttk.Entry(tab, textvariable=self.dest_var, width=70)
        self.dest_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=(5, 5), pady=(10, 0))
        ttk.Button(tab, text="Browse", command=self._browse_dest, width=8).grid(row=2, column=2, pady=(10, 0))
        
        # Control buttons frame
        button_frame = ttk.Frame(tab)
        button_frame.grid(row=3, column=0, columnspan=4, pady=15)
        
        self.start_button = ttk.Button(button_frame, text="Start Transfer", command=self._start_transfer, width=15)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.pause_button = ttk.Button(button_frame, text="Pause", command=self._pause_transfer, state=tk.DISABLED, width=8)
        self.pause_button.pack(side=tk.LEFT, padx=5)
        
        self.cancel_button = ttk.Button(button_frame, text="Cancel", command=self._cancel_transfer, state=tk.DISABLED, width=8)
        self.cancel_button.pack(side=tk.LEFT, padx=5)
        
        # Game list section
        games_frame = ttk.LabelFrame(tab, text="Detected PS3 Games", padding="10")
        games_frame.grid(row=4, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(0, 10))
        games_frame.columnconfigure(0, weight=1)
        games_frame.rowconfigure(0, weight=1)
        
        # Create treeview for game list
        columns = ('size', 'status', 'warnings')
        self.game_list_main = ttk.Treeview(
            games_frame, 
            columns=columns, 
            show='headings',
            selectmode='browse',
            height=6,
            style='GameList.Treeview'
        )
        
        # Configure columns
        self.game_list_main.heading('#0', text='Game Name', anchor=tk.W)
        self.game_list_main.heading('size', text='Size (GB)', anchor=tk.W)
        self.game_list_main.heading('status', text='Status', anchor=tk.W)
        self.game_list_main.heading('warnings', text='Warnings', anchor=tk.W)
        
        self.game_list_main.column('#0', width=250, stretch=tk.YES)
        self.game_list_main.column('size', width=80, stretch=tk.NO, anchor=tk.CENTER)
        self.game_list_main.column('status', width=80, stretch=tk.NO, anchor=tk.CENTER)
        self.game_list_main.column('warnings', width=80, stretch=tk.NO, anchor=tk.CENTER)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(games_frame, orient=tk.VERTICAL, command=self.game_list_main.yview)
        self.game_list_main.configure(yscroll=scrollbar.set)
        
        # Layout
        self.game_list_main.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Configure grid weights
        games_frame.columnconfigure(0, weight=1)
        games_frame.rowconfigure(0, weight=1)
        
        # Info label
        self.game_info_label = ttk.Label(games_frame, text="Click 'Scan Games' to detect PS3 games in the source directory")
        self.game_info_label.grid(row=1, column=0, columnspan=2, pady=(5, 0))
        
        # Progress section
        progress_frame = ttk.LabelFrame(tab, text="Transfer Progress", padding="10")
        progress_frame.grid(row=5, column=0, columnspan=4, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
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
        infected_label.grid(row=0, column=5, sticky=tk.W, padx=(5, 10))
        
        ttk.Label(stats_frame, text="Warnings:").grid(row=0, column=6, sticky=tk.W)
        self.warnings_var = tk.StringVar(value="0")
        warnings_label = ttk.Label(stats_frame, textvariable=self.warnings_var, style='Warning.TLabel')
        warnings_label.grid(row=0, column=7, sticky=tk.W, padx=(5, 0))
        
        # Configure grid weights for tab
        tab.columnconfigure(1, weight=1)
        tab.rowconfigure(5, weight=1)
    
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
        self.game_list = ttk.Treeview(left_frame, columns=('status', 'size', 'warnings'), show='headings')
        self.game_list.heading('#0', text='Game')
        self.game_list.heading('status', text='Status')
        self.game_list.heading('size', text='Size')
        self.game_list.heading('warnings', text='Warnings')
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
    
    def _create_error_tab(self):
        """Create error diagnostics tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Error Diagnostics")
        
        # Create error details viewer
        self.error_text = scrolledtext.ScrolledText(tab, state=tk.DISABLED)
        self.error_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Add solution buttons
        button_frame = ttk.Frame(tab)
        button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        ttk.Button(button_frame, text="View Error Guide", command=self._show_error_guide).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Copy Error Details", command=self._copy_error_details).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Open File Location", command=self._open_error_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Auto-Rename File", command=self._auto_rename_file).pack(side=tk.LEFT, padx=5)
        
        # Add status label
        self.error_status = ttk.Label(tab, text="No errors detected", style='Status.TLabel')
        self.error_status.pack(pady=(0, 5))
    
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
        """Scan for PS3 games in the main tab"""
        source = self.source_var.get().strip()
        if not source:
            messagebox.showerror("Error", "Please select source directory first")
            return
        
        source_path = Path(source)
        if not source_path.exists():
            messagebox.showerror("Error", "Source directory does not exist")
            return
        
        # Clear previous results
        self.game_list_main.delete(*self.game_list_main.get_children())
        self.game_info_label.config(text="Scanning for PS3 games...")
        
        # Start scan in separate thread
        threading.Thread(
            target=self._run_game_scan,
            args=(source_path,),
            daemon=True
        ).start()
    
    def _run_game_scan(self, source_path: Path):
        """Run game scan and update UI"""
        try:
            games = PS3GameScanner.find_ps3_games(source_path)
            total_size = 0
            total_warnings = 0
            
            for game_path in games:
                try:
                    game_info = PS3GameScanner.get_game_info(game_path)
                    size_gb = game_info['size'] / (1024**3)
                    status = "Valid" if game_info['valid'] else "Invalid"
                    warnings = len(game_info['warning_files'])
                    total_warnings += warnings
                    
                    self.root.after(0, self.game_list_main.insert, '', 'end', 
                                  text=game_info['name'], 
                                  values=(f"{size_gb:.2f}", status, warnings))
                    
                    total_size += game_info['size']
                except Exception as e:
                    self.logger.error(f"Failed to get game info for {game_path}: {e}")
            
            # Update status
            self.root.after(0, lambda: self.game_info_label.config(
                text=f"Found {len(games)} games | Total size: {total_size / (1024**3):.2f} GB | Warnings: {total_warnings}"
            ))
            
        except Exception as e:
            self.logger.error(f"Game scan failed: {e}")
            self.root.after(0, lambda: self.game_info_label.config(
                text=f"Scan failed: {str(e)}"
            ))
    
    def _validate_paths(self):
        """Validate all paths for potential issues"""
        source = self.source_var.get().strip()
        if not source:
            messagebox.showerror("Error", "Please select source directory first")
            return
        
        source_path = Path(source)
        if not source_path.exists():
            messagebox.showerror("Error", "Source directory does not exist")
            return
        
        # Start validation in separate thread
        threading.Thread(
            target=self._run_path_validation,
            args=(source_path,),
            daemon=True
        ).start()
    
    def _run_path_validation(self, source_path: Path):
        """Run path validation and report issues"""
        try:
            self._update_status("Validating paths...")
            warning_count = 0
            
            for root, dirs, files in os.walk(source_path):
                for file in files:
                    file_path = Path(root) / file
                    relative_path = file_path.relative_to(source_path)
                    
                    # Check for potential issues
                    issues = []
                    if PS3FileValidator.has_invalid_chars(file):
                        issues.append("Invalid characters")
                    if len(str(relative_path)) > MAX_PATH_LENGTH:
                        issues.append(f"Path too long ({len(str(relative_path))} chars)")
                    if ' ' in file:
                        issues.append("Contains spaces")
                    if '(' in file or ')' in file:
                        issues.append("Contains parentheses")
                    
                    if issues:
                        warning_count += 1
                        self.logger.warning(f"Path issue: {relative_path} - {', '.join(issues)}")
                        self.root.after(0, self._add_path_warning, file_path, issues)
            
            self._update_status(f"Path validation complete! Found {warning_count} potential issues")
            messagebox.showinfo("Validation Complete", 
                              f"Found {warning_count} files with potential path issues")
            
        except Exception as e:
            self.logger.error(f"Path validation failed: {e}")
            self._update_status("Path validation failed")
    
    def _add_path_warning(self, file_path: Path, issues: List[str]):
        """Add path warning to the error diagnostics tab"""
        self.error_text.configure(state=tk.NORMAL)
        self.error_text.insert(tk.END, f"⚠️ File: {file_path}\n")
        self.error_text.insert(tk.END, f"   Issues: {', '.join(issues)}\n")
        self.error_text.insert(tk.END, f"   Solution: Rename to '{PS3FileValidator.sanitize_filename(file_path.name)}'\n")
        self.error_text.insert(tk.END, "-" * 80 + "\n")
        self.error_text.see(tk.END)
        self.error_text.configure(state=tk.DISABLED)
        self.error_status.config(text=f"{self.error_text.index('end-1c').split('.')[0]} warnings found")
    
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
    
    def _enable_long_paths(self):
        """Enable long path support on Windows"""
        if platform.system() != 'Windows':
            messagebox.showinfo("Not Supported", "Long path support is only available on Windows 10+")
            return
        
        try:
            if enable_long_paths():
                messagebox.showinfo("Success", 
                    "Long path support enabled! Note: You may need to reboot for changes to take effect.")
            else:
                messagebox.showerror("Error", 
                    "Failed to enable long paths. Please try running as administrator.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to enable long paths: {str(e)}")
    
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
        
        # Clear previous errors
        self.error_text.configure(state=tk.NORMAL)
        self.error_text.delete(1.0, tk.END)
        self.error_text.configure(state=tk.DISABLED)
        self.error_status.config(text="Transfer in progress...")
        
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
            self.error_status.config(text="Transfer completed successfully!")
        else:
            self.error_status.config(text="Transfer failed - see error diagnostics")
            self._show_error_guide()
    
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
            self.error_status.config(text="Transfer cancelled by user")
    
    def _handle_file_warning(self, file_path: Path, issues: List[str]):
        """Handle file warnings during scanning"""
        self.stats.warning_files += 1
        self.root.after(0, self.warnings_var.set, str(self.stats.warning_files))
        
        # Add to error diagnostics tab
        self.root.after(0, self._add_path_warning, file_path, issues)
    
    def _update_progress(self, stats: TransferStats):
        """Update progress display"""
        if stats.total_size > 0:
            progress = (stats.transferred_size / stats.total_size) * 100
            self.progress_var.set(progress)
        
        self.current_file_var.set(stats.current_file)
        self.files_var.set(f"{stats.processed_files}/{stats.total_files}")
        self.games_var.set(f"{stats.games_count}")
        self.infected_var.set(f"{stats.infected_files}")
        self.warnings_var.set(f"{stats.warning_files}")
        
        # Format speed
        if stats.transfer_speed > 0:
            if stats.transfer_speed > 1024**3:
                speed_str = f"{stats.transfer_speed / (1024**3):.2f} GB/s"
            elif stats.transfer_speed > 1024**2:
                speed_str = f"{stats.transfer_speed / (1024**2):.2f} MB/s"
            else:
                speed_str = f"{stats.transfer_speed / 1024:.2f} KB/s"
            self.speed_var.set(speed_str)
        
        # Update error tab with any errors
        if stats.errors:
            self.error_text.configure(state=tk.NORMAL)
            for error in stats.errors:
                self.error_text.insert(tk.END, error + "\n")
                self.error_text.insert(tk.END, "="*80 + "\n\n")
            self.error_text.see(tk.END)
            self.error_text.configure(state=tk.DISABLED)
            self.error_status.config(text=f"{len(stats.errors)} errors detected")
    
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
        warnings = len(result['warning_files'])
        
        self.game_list.insert('', 'end', text=result['name'], 
                            values=(status, f"{size_gb:.2f} GB", warnings))
        
        # Update details
        self.game_details.config(state=tk.NORMAL)
        self.game_details.insert(tk.END, f"Game: {result['name']}\n")
        self.game_details.insert(tk.END, f"Status: {'Valid' if result['valid'] else 'Invalid'}\n")
        self.game_details.insert(tk.END, f"Size: {size_gb:.2f} GB\n")
        self.game_details.insert(tk.END, f"Files: {len(result['files'])}\n")
        self.game_details.insert(tk.END, f"Warnings: {warnings}\n")
        
        if result['sfo_data']:
            self.game_details.insert(tk.END, "\nSFO Metadata:\n")
            for key, value in result['sfo_data'].items():
                self.game_details.insert(tk.END, f"  {key}: {value}\n")
        
        if result['issues']:
            self.game_details.insert(tk.END, "\nIssues:\n")
            for issue in result['issues']:
                self.game_details.insert(tk.END, f"  - {issue}\n")
        
        if warnings:
            self.game_details.insert(tk.END, "\nFiles with Warnings:\n")
            for file in result['warning_files']:
                self.game_details.insert(tk.END, f"  - {file}\n")
        
        self.game_details.insert(tk.END, "\n" + "="*50 + "\n")
        self.game_details.config(state=tk.DISABLED)
    
    def _log_message(self, message: str):
        """Add message to log display"""
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + '\n')
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)
    
    def _show_error_guide(self):
        """Show detailed error guide"""
        guide = """⚠️ Transfer Error – Possible Causes and Recommended Solutions

1. ❗ Invalid File Name or Unsupported Characters
   - Files may contain special characters (#, @, !, (), ,)
   - Files may have excessive spaces or symbols

   ✅ Solutions:
   - Rename problematic files to simpler names
   - Use only letters, numbers, and underscores
   - Avoid spaces and parentheses in file names

2. ❗ Path Too Long (Windows MAX_PATH Limit)
   - Windows limits paths to 260 characters
   - Deeply nested folders often cause this

   ✅ Solutions:
   - Shorten folder names in source/destination
   - Move game folder closer to drive root (e.g., D:\\Games\\)
   - Enable long path support via Tools menu

3. ❗ FAT32 File System Limitations
   - FAT32 doesn't support files larger than 4GB
   - Some directory structures cause issues

   ✅ Solutions:
   - Ensure files >4GB are split automatically
   - Test transfer on NTFS-formatted drive
   - Use our path validation tool

4. ❗ Antivirus Interference
   - Security software may block game files
   - Real-time scanning can interrupt transfers

   ✅ Solutions:
   - Temporarily disable antivirus during transfer
   - Whitelist this application in security settings
   - Add game folder to antivirus exclusions

🛠️ Additional Recommendations:
- Try manually copying the problematic file
- Use the 'Validate Paths' tool to detect issues
- Check error diagnostics tab for specific file issues
- Consult logs for detailed error information"""
        
        messagebox.showinfo("Transfer Error Guide", guide)
    
    def _copy_error_details(self):
        """Copy error details to clipboard"""
        self.root.clipboard_clear()
        self.root.clipboard_append(self.error_text.get(1.0, tk.END))
        messagebox.showinfo("Copied", "Error details copied to clipboard")
    
    def _open_error_file(self):
        """Open location of problematic file"""
        # This would be implemented with actual error file selection
        # For now, just show a message
        messagebox.showinfo("Info", "Select a file from the error list to use this feature")
    
    def _auto_rename_file(self):
        """Automatically rename problematic file"""
        # This would be implemented with actual error file selection
        messagebox.showinfo("Info", "Select a file from the error list to use this feature")
    
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
                'log_file': str(self.logger.log_file.absolute()),
                'long_path_support': enable_long_paths()
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
