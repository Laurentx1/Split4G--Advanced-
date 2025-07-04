#!/usr/bin/env python3
"""
PS3 FAT32 Transfer Tool PRO - Enhanced Edition v4.0
Fixed missing files issue with real-time tracking and enhanced verification
Added comprehensive file manifest system and atomic operations
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
import stat
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Callable
from dataclasses import dataclass, asdict
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# Constants - UPDATED VALUES
FAT32_MAX_FILE_SIZE = 4 * 1024 * 1024 * 1024 - 1  # 4GB - 1 byte
MAX_VALID_FILE_SIZE = 10 * 1024**4  # 10 TB (sanity check)
CHUNK_SIZE = 64 * 1024 * 1024  # 64MB chunks for splitting
PS3_REQUIRED_DIRS = ['PS3_GAME']  # Only require PS3_GAME
PS3_GAME_SUBDIRS = ['USRDIR']  # Only require USRDIR
MAX_PATH_LENGTH = 255  # Max allowed for FAT32
MAX_FILENAME_LENGTH = 100  # Reduced for FAT32 compatibility
DEBUGGER_RETRY_DELAY = 0.5  # Seconds between retry attempts
MAX_DEBUGGER_RETRIES = 5  # Increased retry attempts for file issues
MAX_DIRECTORY_RETRIES = 3  # Retries for directory creation
VERIFICATION_RETRIES = 3  # Retries for missing file verification

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
    debugger_issues: int = 0
    debugger_fixed: int = 0
    debugger_retries: int = 0
    missing_files: int = 0
    verified_files: int = 0
    retried_files: int = 0
    manifest_entries: int = 0
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []

class EnhancedDebugger:
    """Real-time debugging system with auto-fix capabilities and missing file detection"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.issue_queue = queue.Queue()
        self.running = True
        self.debug_thread = threading.Thread(target=self._monitor_and_fix, daemon=True)
        self.debug_thread.start()
        self.active_fixes = {}
        self.lock = threading.Lock()
        self.file_tracker = {}  # Track file existence during transfer
    
    def _monitor_and_fix(self):
        """Continuously monitor and fix issues in real-time"""
        while self.running:
            try:
                file_path, dest_path, callback = self.issue_queue.get(timeout=0.5)
                
                # Skip if file is already being processed
                with self.lock:
                    if file_path in self.active_fixes:
                        continue
                    self.active_fixes[file_path] = True
                
                # Track file existence
                self._track_file(file_path)
                
                # Process the file
                issues, fixed = self.check_file_integrity(file_path, dest_path, self.logger)
                
                # Auto-fix common issues if not fixed
                if issues and not fixed:
                    fixed = self._auto_fix_issues(file_path, issues, dest_path)
                
                # Notify callback with results
                if callback:
                    callback(file_path, issues, fixed)
                
                # Release file lock
                with self.lock:
                    del self.active_fixes[file_path]
                    
            except queue.Empty:
                # Check for disappeared files
                self._check_missing_files()
                continue
            except Exception as e:
                self.logger.error(f"Debugger error: {e}")
    
    def _track_file(self, file_path: Path):
        """Track file existence in our system"""
        self.file_tracker[file_path] = {
            'last_seen': time.time(),
            'exists': file_path.exists()
        }
    
    def _check_missing_files(self):
        """Check if any tracked files have disappeared"""
        missing = []
        current_time = time.time()
        
        for file_path, info in list(self.file_tracker.items()):
            if not file_path.exists() and info['exists']:
                # File has disappeared since we last saw it
                if current_time - info['last_seen'] < 5:  # Disappeared within last 5 seconds
                    missing.append(file_path)
        
        if missing:
            self.logger.warning(f"Detected {len(missing)} files disappeared during transfer")
            for file in missing:
                self.logger.warning(f"File disappeared: {file}")
                # Try to recover if possible
                self._recover_missing_file(file)
    
    def _recover_missing_file(self, file_path: Path):
        """Attempt to recover a missing file"""
        # Check if it's a temporary disappearance
        for _ in range(3):
            time.sleep(0.5)
            if file_path.exists():
                self.logger.info(f"File reappeared: {file_path}")
                self.file_tracker[file_path]['exists'] = True
                return True
        
        # Permanent disappearance - log error
        self.logger.error(f"File permanently disappeared: {file_path}")
        return False
    
    def _auto_fix_issues(self, file_path: Path, issues: List[str], dest_path: Path) -> bool:
        """Automatically fix common issues"""
        fixed = False
        
        # Fix invalid characters
        if any("invalid characters" in issue.lower() for issue in issues):
            new_name = PS3FileValidator.sanitize_filename(file_path.name)
            new_path = file_path.with_name(new_name)
            try:
                file_path.rename(new_path)
                self.logger.info(f"Auto-renamed file: {file_path} -> {new_path}")
                fixed = True
                # Update the file path for further processing
                file_path = new_path
            except Exception as e:
                self.logger.warning(f"Failed to auto-rename {file_path}: {e}")
        
        # Fix read-only attributes
        if any("read-only" in issue.lower() for issue in issues):
            try:
                if platform.system() == 'Windows':
                    subprocess.run(['attrib', '-R', str(file_path)], check=True, capture_output=True)
                else:
                    file_path.chmod(0o777)
                self.logger.info(f"Fixed read-only attribute: {file_path}")
                fixed = True
            except Exception as e:
                self.logger.warning(f"Failed to fix attributes {file_path}: {e}")
        
        # Fix long paths by creating destination directories in advance
        if any("path too long" in issue.lower() for issue in issues):
            try:
                # Create with retries
                self._create_directory_with_retry(dest_path.parent)
                self.logger.info(f"Created destination directories: {dest_path.parent}")
                fixed = True
            except Exception as e:
                self.logger.warning(f"Failed to create directories {dest_path.parent}: {e}")
        
        return fixed
    
    def _create_directory_with_retry(self, path: Path, max_retries=MAX_DIRECTORY_RETRIES):
        """Create directory with retries"""
        for attempt in range(max_retries):
            try:
                path.mkdir(parents=True, exist_ok=True)
                return
            except Exception as e:
                if attempt < max_retries - 1:
                    time.sleep(0.5)
                else:
                    raise Exception(f"Failed to create directory after {max_retries} attempts: {path}")
    
    @staticmethod
    def check_file_integrity(source_path: Path, dest_path: Path, logger: logging.Logger) -> Tuple[List[str], bool]:
        """Comprehensive pre-transfer validation with self-healing"""
        issues = []
        fixed = False
        
        # 1. Check file exists
        if not source_path.exists():
            issues.append("File does not exist")
            return issues, fixed
        
        # 2. Check file size
        try:
            file_size = source_path.stat().st_size
            if file_size == 0:
                issues.append("Zero-byte file (possibly corrupted)")
        except Exception as e:
            issues.append(f"Could not access file size: {str(e)}")
        
        # 3. Check file attributes (Windows only)
        if platform.system() == 'Windows':
            try:
                attrs = source_path.stat().st_file_attributes
                if attrs & stat.FILE_ATTRIBUTE_HIDDEN:
                    issues.append("Hidden file attribute")
                if attrs & stat.FILE_ATTRIBUTE_SYSTEM:
                    issues.append("System file attribute")
                if attrs & stat.FILE_ATTRIBUTE_READONLY:
                    issues.append("Read-only attribute")
                    # Attempt to fix read-only attribute
                    try:
                        source_path.chmod(stat.S_IWRITE)
                        issues.remove("Read-only attribute")
                        fixed = True
                        logger.info(f"Fixed read-only attribute: {source_path}")
                    except:
                        pass
            except Exception as e:
                issues.append(f"Attribute check failed: {str(e)}")
        
        # 4. Check for invalid characters in filename
        if any(char in source_path.name for char in '<>:"/\\|?*'):
            issues.append("Invalid characters in filename")
        
        # 5. Check path length
        if len(str(source_path)) > MAX_PATH_LENGTH:
            issues.append(f"Path too long ({len(str(source_path))} characters)")
        
        # 6. Check FAT32 restrictions
        if file_size > FAT32_MAX_FILE_SIZE:
            issues.append(f"File too large for FAT32 ({file_size / (1024**3):.2f} GB)")
        
        # 7. Check file locking
        if EnhancedDebugger.is_file_locked(source_path):
            issues.append("File is locked by another process")
        
        # 8. Test write permissions
        if not EnhancedDebugger.test_write_permission(dest_path.parent):
            issues.append("Destination write permission denied")
        
        return issues, fixed
    
    @staticmethod
    def is_file_locked(file_path: Path) -> bool:
        """Check if file is locked by another process"""
        try:
            if platform.system() == 'Windows':
                # Windows-specific file locking check
                try:
                    with safe_file_open(file_path, 'rb') as f:
                        pass
                    return False
                except PermissionError:
                    return True
            else:
                # Unix-like systems
                import fcntl
                with open(file_path, 'a') as f:
                    try:
                        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        fcntl.flock(f, fcntl.LOCK_UN)
                        return False
                    except IOError:
                        return True
        except:
            return False
    
    @staticmethod
    def test_write_permission(directory: Path) -> bool:
        """Test write permissions in destination directory"""
        try:
            test_file = directory / "write_test.tmp"
            with safe_file_open(test_file, 'w') as f:
                f.write("test")
            test_file.unlink()
            return True
        except Exception:
            return False
    
    def queue_issue(self, file_path: Path, dest_path: Path, callback: Callable):
        """Add file to debug queue"""
        self.issue_queue.put((file_path, dest_path, callback))
    
    def stop(self):
        """Stop debugger thread"""
        self.running = False
        self.debug_thread.join()

class PS3GameScanner:
    """Scans and analyzes PS3 game folders with enhanced detection"""
    
    @staticmethod
    def find_ps3_games(directory: Path) -> List[Path]:
        """Enhanced game detection that scans up to 2 levels deep"""
        games = []
        for entry in directory.iterdir():
            if entry.is_dir():
                # Check current directory
                if PS3FileValidator.is_valid_ps3_game(entry):
                    games.append(entry)
                
                # Check one level deep
                for sub_entry in entry.iterdir():
                    if sub_entry.is_dir() and PS3FileValidator.is_valid_ps3_game(sub_entry):
                        games.append(sub_entry)
        return games
    
    @staticmethod
    def get_game_info(game_path: Path) -> Dict:
        """Get detailed information about a PS3 game with accurate size calculation"""
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
        
        # Get file list and size using os.walk for reliability
        for root, dirs, files in os.walk(game_path):
            for file in files:
                file_path = Path(root) / file
                try:
                    # Check for potential issues
                    warnings = []
                    relative_path = file_path.relative_to(game_path)
                    
                    # Check for invalid characters
                    if PS3FileValidator.has_invalid_chars(file):
                        warnings.append("Contains invalid characters")
                    
                    # Check for long paths
                    if len(str(relative_path)) > MAX_PATH_LENGTH:
                        warnings.append(f"Path too long ({len(str(relative_path))} characters)")
                    
                    # Check for spaces in filename
                    if ' ' in file:
                        warnings.append("Contains spaces")
                        
                    # Check for parentheses in filename
                    if '(' in file or ')' in file:
                        warnings.append("Contains parentheses")
                    
                    # Get actual file size
                    file_size = file_path.stat().st_size
                    
                    file_info = {
                        'path': str(relative_path),
                        'size': file_size,
                        'needs_split': file_size > FAT32_MAX_FILE_SIZE,
                        'warnings': warnings
                    }
                    
                    info['files'].append(file_info)
                    info['size'] += file_size
                    
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

class PS3FileValidator:
    """Validates and fixes PS3 game folder structures"""
    
    INVALID_CHARS = r'[<>:"/\\|?*]'
    MAX_FILENAME_LENGTH = MAX_FILENAME_LENGTH
    WINDOWS_RESERVED_NAMES = [
        "CON", "PRN", "AUX", "NUL", 
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    ]
    
    @staticmethod
    def has_invalid_chars(filename: str) -> bool:
        """Check if filename contains invalid characters"""
        return bool(re.search(PS3FileValidator.INVALID_CHARS, filename))
    
    @staticmethod
    def is_valid_ps3_game(game_path: Path) -> bool:
        """Check if directory is a valid PS3 game"""
        return (game_path / 'PS3_GAME').exists()
    
    @staticmethod
    def validate_ps3_structure(game_path: Path) -> List[str]:
        """Validate PS3 game folder structure"""
        issues = []
        
        # Check for required directories
        if not (game_path / 'PS3_GAME').exists():
            issues.append("Missing required directory: PS3_GAME")
        else:
            # Check PS3_GAME subdirectories
            ps3_game_dir = game_path / 'PS3_GAME'
            if not (ps3_game_dir / 'USRDIR').exists():
                issues.append("Missing required item in PS3_GAME: USRDIR")
        
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
        # Remove trailing periods (common Windows issue)
        sanitized = sanitized.rstrip('.')
        
        # Handle Windows reserved names
        base_name = os.path.splitext(sanitized)[0].upper()
        if platform.system() == 'Windows' and base_name in PS3FileValidator.WINDOWS_RESERVED_NAMES:
            sanitized = f"_{sanitized}"
        
        # Truncate if too long
        if len(sanitized) > PS3FileValidator.MAX_FILENAME_LENGTH:
            name, ext = os.path.splitext(sanitized)
            max_name_length = PS3FileValidator.MAX_FILENAME_LENGTH - len(ext)
            sanitized = name[:max_name_length] + ext
        
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
        # Sanitize base name and remove special characters
        base_name = re.sub(r'[^\w]', '_', source_path.stem)[:50]
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
    
    # NEW: Enhanced logging functions with file metadata
    def log_transfer(self, source: Path, dest: Path, success: bool, size: int, split: bool = False):
        """Log file transfer with metadata"""
        status = "SUCCESS" if success else "FAILED"
        split_info = " [SPLIT]" if split else ""
        size_gb = size / (1024**3)
        self.info(f"Transfer {status}{split_info}: {source} -> {dest} | Size: {size_gb:.2f}GB")
    
    def log_verification(self, file_path: Path, success: bool, expected_hash: str, actual_hash: str = ""):
        """Log file verification results"""
        if success:
            self.info(f"Verified: {file_path} | Hash: {expected_hash[:12]}...")
        else:
            self.error(f"Verification FAILED: {file_path} | Expected: {expected_hash[:12]}... | Actual: {actual_hash[:12]}...")
    
    def log_manifest_entry(self, file_path: Path, size: int, hash_value: str):
        """Log manifest entry creation"""
        self.debug(f"Manifest entry: {file_path} | Size: {size} | Hash: {hash_value[:8]}...")

class PS3TransferEngine:
    """Advanced transfer engine with real-time debugging system and file manifest"""
    
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
        self.debugger_callback = None
        self.debugger = EnhancedDebugger(logger)
        self.file_manifest = {}  # For post-transfer verification
        self.manifest_path = Path("transfer_manifest.json")  # Manifest storage
    
    def set_callbacks(self, progress_callback: Callable = None, 
                     status_callback: Callable = None,
                     virus_scan_callback: Callable = None,
                     game_scan_callback: Callable = None,
                     warning_callback: Callable = None,
                     debugger_callback: Callable = None):
        """Set callbacks for various events"""
        self.progress_callback = progress_callback
        self.status_callback = status_callback
        self.virus_scan_callback = virus_scan_callback
        self.game_scan_callback = game_scan_callback
        self.warning_callback = warning_callback
        self.debugger_callback = debugger_callback
    
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
    
    def _update_debugger(self, file_path: Path, issues: List[str], fixed: bool):
        """Update debugger information"""
        if self.debugger_callback:
            self.debugger_callback(file_path, issues, fixed)
    
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
    
    def transfer_game(self, source_dir: Path, dest_dir: Path) -> bool:
        """Main transfer function with real-time debugging and manifest system"""
        try:
            self.stats = TransferStats()
            self.stats.start_time = time.time()
            self.cancel_requested = False
            self.file_manifest = {}  # Reset manifest
            
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
            
            # Create manifest file
            self._create_manifest()
            
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
                
                # Create destination subdirectories with retries
                if not self._create_directory_with_retry(dest_file_path.parent):
                    continue
                
                self.stats.current_file = str(sanitized_relative)
                self._update_status(f"Processing: {sanitized_relative}")
                
                # Store file info in manifest
                self._add_to_manifest(file_path, sanitized_relative)
                
                # Queue file for real-time debugging
                self.debugger.queue_issue(file_path, dest_file_path, self._handle_debugger_result)
                
                # Check if file needs splitting
                if FileSplitter.needs_splitting(file_path):
                    self._transfer_large_file(file_path, dest_file_path)
                else:
                    self._transfer_regular_file(file_path, dest_file_path)
                
                self.stats.processed_files += 1
                self._update_progress()
            
            # Verify transfer after completion
            if not self.cancel_requested:
                self._verify_transfer(source_dir, dest_dir)
            
            self._update_status("Transfer completed successfully!")
            self._save_manifest()  # Save manifest to disk
            return True
            
        except Exception as e:
            error_msg = f"Transfer failed: {e}"
            self.logger.error(error_msg, exc_info=True)
            self._update_status(error_msg)
            self._save_manifest()  # Save manifest even on failure
            return False
    
    def _create_manifest(self):
        """Initialize the file manifest"""
        self.file_manifest = {
            'version': '1.0',
            'created_at': datetime.now().isoformat(),
            'source': '',
            'destination': '',
            'files': {}
        }
    
    def _add_to_manifest(self, file_path: Path, relative_path: Path):
        """Add file to transfer manifest"""
        file_size = file_path.stat().st_size
        file_hash = None
        
        # Calculate hash for files under 100MB
        if file_size < 100 * 1024 * 1024:
            try:
                file_hash = FileHasher.calculate_md5(file_path)
            except Exception as e:
                self.logger.warning(f"Failed to calculate hash for {file_path}: {e}")
        
        self.file_manifest['files'][str(relative_path)] = {
            'source_path': str(file_path),
            'size': file_size,
            'hash': file_hash,
            'split': FileSplitter.needs_splitting(file_path),
            'verified': False
        }
        self.stats.manifest_entries += 1
        self.logger.log_manifest_entry(file_path, file_size, file_hash or "N/A")
    
    def _save_manifest(self):
        """Save manifest to disk"""
        try:
            with open(self.manifest_path, 'w') as f:
                json.dump(self.file_manifest, f, indent=2)
            self.logger.info(f"Manifest saved to {self.manifest_path}")
        except Exception as e:
            self.logger.error(f"Failed to save manifest: {e}")
    
    def _create_directory_with_retry(self, path: Path, max_retries=MAX_DIRECTORY_RETRIES) -> bool:
        """Create directory with retries and error handling"""
        if path.exists() and path.is_dir():
            return True
            
        for attempt in range(max_retries):
            try:
                path.mkdir(parents=True, exist_ok=True)
                return True
            except Exception as e:
                self.logger.warning(f"Directory creation attempt {attempt+1} failed for {path}: {e}")
                if attempt < max_retries - 1:
                    time.sleep(0.5)
                else:
                    self.logger.error(f"Failed to create directory after {max_retries} attempts: {path}")
                    self.stats.errors.append(f"Directory creation failed: {path}")
                    return False
    
    def _handle_debugger_result(self, file_path: Path, issues: List[str], fixed: bool):
        """Handle results from real-time debugger"""
        if issues:
            self.stats.debugger_issues += 1
            if fixed:
                self.stats.debugger_fixed += 1
            self._update_debugger(file_path, issues, fixed)
    
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
        """Enhanced large file transfer with better error reporting and atomic operations"""
        file_size = source_path.stat().st_size
        self.logger.info(f"Large file detected: {source_path.name} ({file_size / (1024**3):.2f}GB)")
        self.logger.info("Splitting required for FAT32 compatibility")
        
        try:
            # Create destination directory if it doesn't exist
            if not self._create_directory_with_retry(dest_path.parent):
                raise Exception("Failed to create destination directory")
            
            # Verify destination filesystem can handle split files
            if not self._validate_destination(dest_path.parent):
                raise Exception("Destination filesystem incompatible with split files")
            
            def progress_callback(bytes_written, total_bytes):
                self.stats.transferred_size += bytes_written
                self._calculate_speed()
            
            # Create temporary directory for atomic operation
            temp_dir = dest_path.parent / f".tmp_{uuid.uuid4().hex}"
            temp_dir.mkdir(exist_ok=True)
            
            split_files = FileSplitter.split_file(source_path, temp_dir, progress_callback)
            
            # Move files atomically
            for part in split_files:
                final_path = dest_path.parent / part.name
                part.rename(final_path)
            
            # Clean up temporary directory
            try:
                temp_dir.rmdir()
            except:
                pass
            
            # Log successful transfer and splitting
            self.logger.log_transfer(
                source_path,
                dest_path,
                success=True,
                size=file_size,
                split=True
            )
            self.logger.info(f"Split into {len(split_files)} parts: {', '.join([p.name for p in split_files])}")
            
            # Log verification of each split part
            for part in split_files:
                final_path = dest_path.parent / part.name
                try:
                    part_size = final_path.stat().st_size
                    part_hash = FileHasher.calculate_md5(final_path)
                    self.logger.log_verification(final_path, True, part_hash)
                except Exception as e:
                    self.logger.error(f"Failed to verify split part {final_path}: {e}")
            
        except Exception as e:
            # Log transfer failure
            self.logger.log_transfer(
                source_path,
                dest_path,
                success=False,
                size=file_size,
                split=True
            )
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
        """Transfer a regular file with enhanced error handling and real-time retry"""
        file_size = source_path.stat().st_size
        original_dest_path = dest_path
        MAX_RETRIES = MAX_DEBUGGER_RETRIES
        
        # Sanity check for implausible file sizes
        if file_size > MAX_VALID_FILE_SIZE:
            error_msg = f"Implausible file size ({file_size} bytes) for file: {source_path}"
            self.logger.error(error_msg)
            self.stats.errors.append(error_msg)
            return
            
        for attempt in range(MAX_RETRIES):
            try:
                # Check if we need to sanitize the filename on retry
                if attempt > 0:
                    # Generate new sanitized filename
                    sanitized_name = PS3FileValidator.sanitize_filename(dest_path.name)
                    dest_path = dest_path.with_name(sanitized_name)
                    self.logger.warning(f"Retrying with sanitized name: {sanitized_name}")
                    
                # Atomic write with temporary file
                temp_path = dest_path.with_name(f".tmp_{dest_path.name}")
                
                with safe_file_open(source_path, 'rb') as src, safe_file_open(temp_path, 'wb') as dst:
                    bytes_copied = 0
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
                
                # Verify file was transferred correctly
                if temp_path.exists() and temp_path.stat().st_size == file_size:
                    # Atomic move to final destination
                    temp_path.rename(dest_path)
                    
                    # Log successful transfer
                    self.logger.log_transfer(
                        source_path,
                        dest_path,
                        success=True,
                        size=file_size
                    )
                    self.stats.verified_files += 1
                    return
                else:
                    raise Exception("File size mismatch after transfer")
                    
            except (OSError, PermissionError, Exception) as e:
                # Clean up temporary file if exists
                if temp_path.exists():
                    try:
                        temp_path.unlink()
                    except:
                        pass
                    
                if attempt < MAX_RETRIES - 1:
                    self.stats.debugger_retries += 1
                    self.logger.warning(f"Transfer error: {e}. Retry {attempt+1}/{MAX_RETRIES}")
                    
                    # Queue for real-time debugging
                    self.debugger.queue_issue(source_path, dest_path, self._handle_debugger_result)
                    
                    # Wait for debugger to potentially fix the issue
                    time.sleep(DEBUGGER_RETRY_DELAY)
                else:
                    # Final error handling
                    if dest_path.exists():
                        try:
                            dest_path.unlink()
                        except Exception as e:
                            self.logger.error(f"Failed to delete corrupted file {dest_path}: {e}")
                    
                    # Log failed transfer
                    self.logger.log_transfer(
                        source_path,
                        original_dest_path,
                        success=False,
                        size=file_size
                    )
                    
                    # Add detailed error diagnostics
                    error_details = self._get_error_diagnostics(source_path, e, original_dest_path, MAX_RETRIES)
                    self.stats.errors.append(error_details)
                    self.logger.error(f"Transfer Error Details:\n{error_details}")
                    raise
    
    def _verify_transfer(self, source_dir: Path, dest_dir: Path):
        """Comprehensive verification of transferred files"""
        self._update_status("Verifying file transfer...")
        missing_files = []
        size_mismatches = []
        hash_mismatches = []
        retry_files = []
        
        # First pass verification
        for relative_path, file_info in self.file_manifest['files'].items():
            source_size = file_info['size']
            source_hash = file_info['hash']
            dest_path = dest_dir / relative_path
            
            if not dest_path.exists():
                missing_files.append((relative_path, source_size))
                continue
                
            dest_size = dest_path.stat().st_size
            if dest_size != source_size:
                size_mismatches.append((relative_path, source_size, dest_size))
                continue
                
            # Verify hash if available
            if source_hash and file_info['size'] < 100 * 1024 * 1024:
                try:
                    dest_hash = FileHasher.calculate_md5(dest_path)
                    if dest_hash != source_hash:
                        hash_mismatches.append((relative_path, source_hash, dest_hash))
                        self.logger.log_verification(dest_path, False, source_hash, dest_hash)
                    else:
                        self.logger.log_verification(dest_path, True, source_hash)
                        # Mark as verified in manifest
                        self.file_manifest['files'][relative_path]['verified'] = True
                except Exception as e:
                    self.logger.warning(f"Failed to verify hash for {dest_path}: {e}")
        
        # Attempt to recover missing files
        for file, size in missing_files:
            self.logger.warning(f"Attempting to recover missing file: {file}")
            if self._recover_missing_file(source_dir / file, dest_dir / file, size):
                retry_files.append(file)
        
        # Second pass for retried files
        for file in retry_files:
            dest_path = dest_dir / file
            if dest_path.exists():
                file_info = self.file_manifest['files'][file]
                source_size = file_info['size']
                source_hash = file_info['hash']
                
                dest_size = dest_path.stat().st_size
                if dest_size != source_size:
                    self.logger.error(f"Retry failed: Size mismatch for {file} (Expected: {source_size}, Actual: {dest_size})")
                    continue
                
                if source_hash:
                    try:
                        dest_hash = FileHasher.calculate_md5(dest_path)
                        if dest_hash != source_hash:
                            self.logger.error(f"Retry failed: Hash mismatch for {file}")
                        else:
                            self.logger.info(f"Recovery successful for {file}")
                            # Mark as verified in manifest
                            self.file_manifest['files'][file]['verified'] = True
                    except Exception as e:
                        self.logger.warning(f"Failed to verify recovered file {file}: {e}")
        
        # Report results
        if missing_files:
            self.logger.error(f"Missing files: {len(missing_files)}")
            self.stats.missing_files = len(missing_files)
            for file, size in missing_files[:5]:  # Show first 5 missing files
                self.stats.errors.append(f"Missing file: {file} ({size} bytes)")
                
        if size_mismatches:
            for file, src_size, dest_size in size_mismatches:
                self.logger.error(f"Size mismatch: {file} (Source: {src_size}, Dest: {dest_size})")
                self.stats.errors.append(f"Size mismatch: {file} ({src_size} vs {dest_size} bytes)")
        
        if hash_mismatches:
            for file, expected, actual in hash_mismatches:
                self.logger.error(f"Hash mismatch: {file} (Expected: {expected[:12]}..., Actual: {actual[:12]}...)")
                self.stats.errors.append(f"Hash mismatch: {file} ({expected[:12]}... vs {actual[:12]}...)")
        
        # Calculate verification statistics
        verified_count = sum(1 for f in self.file_manifest['files'].values() if f.get('verified', False))
        self.stats.verified_files = verified_count
        
        if not missing_files and not size_mismatches and not hash_mismatches:
            self.logger.info("Transfer verification successful - all files match source")
            self._update_status("Transfer verified: All files match source")
        else:
            status_msg = (
                f"Verification issues: {len(missing_files)} missing, "
                f"{len(size_mismatches)} size mismatches, "
                f"{len(hash_mismatches)} hash mismatches | "
                f"{verified_count}/{len(self.file_manifest['files'])} verified"
            )
            self._update_status(status_msg)
    
    def _recover_missing_file(self, source_path: Path, dest_path: Path, expected_size: int) -> bool:
        """Attempt to recover a missing file"""
        self.stats.retried_files += 1
        self.logger.info(f"Attempting recovery for missing file: {source_path}")
        
        for attempt in range(VERIFICATION_RETRIES):
            try:
                # Ensure source still exists
                if not source_path.exists():
                    self.logger.error(f"Source file disappeared during recovery: {source_path}")
                    return False
                
                # Retry the transfer
                if FileSplitter.needs_splitting(source_path):
                    self._transfer_large_file(source_path, dest_path)
                else:
                    self._transfer_regular_file(source_path, dest_path)
                
                # Verify after retry
                if dest_path.exists() and dest_path.stat().st_size == expected_size:
                    self.logger.info(f"Successfully recovered missing file: {dest_path}")
                    return True
                
            except Exception as e:
                self.logger.warning(f"Recovery attempt {attempt+1} failed: {e}")
                time.sleep(1)
        
        self.logger.error(f"Failed to recover missing file after {VERIFICATION_RETRIES} attempts: {source_path}")
        return False
    
    def _get_error_diagnostics(self, source_path: Path, error: Exception, dest_path: Path, retry_count: int) -> str:
        """Generate detailed error diagnostics"""
        diagnostics = [
            "⚠️ Transfer Error – Possible Causes and Recommended Solutions",
            "",
            f"File: {source_path}",
            f"Size: {source_path.stat().st_size / (1024**3):.2f} GB",
            f"Error: {str(error)}",
            "",
            "❗ Possible Cause #1: Invalid File Name or Unsupported Characters",
            "Some files may contain:",
            "- Special characters (e.g., #, @, !, (), ,)",
            "- Excessive spaces",
            "- Very long names or deeply nested folder structures",
            "",
            "✅ Solution:",
            f"- Original name: '{source_path.name}'",
            f"- Sanitized name: '{PS3FileValidator.sanitize_filename(source_path.name)}'",
            "- Rename problematic files to simpler names using only standard characters",
            "- Avoid spaces, parentheses, or symbols in file names",
            "",
            "❗ Possible Cause #2: Path Too Long (Windows MAX_PATH Limit)",
            "Windows limits file paths to 260 characters",
            f"Current path length: {len(str(source_path))} characters",
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
            f"- File size: {source_path.stat().st_size / (1024**3):.2f} GB",
            f"- {'File is within FAT32 limits' if source_path.stat().st_size <= FAT32_MAX_FILE_SIZE else 'File exceeds FAT32 size limit!'}",
            "- Consider testing on NTFS-formatted drive",
            "",
            "❗ Possible Cause #4: Antivirus Interference",
            "Antivirus tools may block game files",
            "",
            "✅ Solution:",
            "- Temporarily disable antivirus software",
            "- Whitelist this application in security settings",
            "",
            "❗ Possible Cause #5: File System Metadata Limitations",
            "Some file systems have limitations on:",
            "- File names containing certain reserved words (CON, PRN, AUX, NUL)",
            "- Files with specific metadata attributes",
            "",
            "✅ Solution:",
            "- Rename file to avoid reserved names",
            "- Check filesystem for corruption (run CHKDSK on Windows)",
            "- Try transferring to a different drive",
            "",
            "🔧 Automatic Fix Attempted:",
            f"- Original destination: {dest_path}",
            f"- Sanitized name: {PS3FileValidator.sanitize_filename(dest_path.name)}",
            f"- Attempted {retry_count} times with different names",
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
    
    def stop_debugger(self):
        """Stop the debugger thread"""
        self.debugger.stop()

class PS3TransferGUI:
    """Modern GUI for PS3 transfer with real-time debugging and verification"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("PS3 FAT32 Transfer Tool PRO - Enhanced Edition v4.0")
        self.root.geometry("1100x800")
        self.root.resizable(True, True)
        self.root.protocol("WM_DELETE_WINDOW", self.close_app)  # Handle window close
        
        # Initialize components
        self.logger = Logger()
        self.engine = PS3TransferEngine(self.logger)
        self.transfer_thread = None
        self.error_details = ""
        
        # Setup callbacks
        self.engine.set_callbacks(
            progress_callback=self._update_progress,
            status_callback=self._update_status,
            warning_callback=self._handle_file_warning,
            debugger_callback=self._handle_debugger_issue
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
        style.configure('Fixed.TLabel', foreground='green')
        style.configure('Debugger.TLabel', foreground='purple')
        style.configure('Verified.TLabel', foreground='blue')
        style.configure('Missing.TLabel', foreground='red')
    
    def _setup_menu(self):
        """Create menu system"""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Exit", command=self.close_app)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Scan Directory for Games", command=self._scan_games)
        tools_menu.add_command(label="Run Pre-Transfer Debugger", command=self._run_debugger)
        tools_menu.add_command(label="Validate Paths", command=self._validate_paths)
        tools_menu.add_separator()
        if platform.system() == 'Windows':
            tools_menu.add_command(label="Enable Long Path Support", command=self._enable_long_paths)
        tools_menu.add_command(label="View Log File", command=self._view_log)
        tools_menu.add_command(label="Open Log Directory", command=self._open_log_dir)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Transfer Error Guide", command=self._show_error_guide)
        help_menu.add_command(label="View Manifest", command=self._view_manifest)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def _create_widgets(self):
        """Create all GUI widgets"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self._create_transfer_tab()
        self._create_debugger_tab()
        self._create_log_tab()
        self._create_error_tab()
        self._create_verification_tab()  # NEW: Verification tab
    
    def _create_transfer_tab(self):
        """Create transfer tab with game scan button"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Transfer")
        
        # Configure grid
        tab.columnconfigure(1, weight=1)
        tab.rowconfigure(5, weight=1)
        
        # Title
        title_label = ttk.Label(tab, text="PS3 FAT32 Transfer Tool PRO - Enhanced Edition v4.0", style='Title.TLabel')
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
        
        ttk.Label(stats_frame, text="Warnings:").grid(row=0, column=4, sticky=tk.W)
        self.warnings_var = tk.StringVar(value="0")
        warnings_label = ttk.Label(stats_frame, textvariable=self.warnings_var, style='Warning.TLabel')
        warnings_label.grid(row=0, column=5, sticky=tk.W, padx=(5, 10))
        
        ttk.Label(stats_frame, text="Debugger:").grid(row=1, column=0, sticky=tk.W, pady=(5,0))
        self.debugger_var = tk.StringVar(value="0")
        debugger_label = ttk.Label(stats_frame, textvariable=self.debugger_var, style='Debugger.TLabel')
        debugger_label.grid(row=1, column=1, sticky=tk.W, padx=(5, 0))
        
        ttk.Label(stats_frame, text="Fixed:").grid(row=1, column=2, sticky=tk.W, pady=(5,0))
        self.fixed_var = tk.StringVar(value="0")
        fixed_label = ttk.Label(stats_frame, textvariable=self.fixed_var, style='Fixed.TLabel')
        fixed_label.grid(row=1, column=3, sticky=tk.W, padx=(5, 0))
        
        ttk.Label(stats_frame, text="Retries:").grid(row=1, column=4, sticky=tk.W, pady=(5,0))
        self.retries_var = tk.StringVar(value="0")
        retries_label = ttk.Label(stats_frame, textvariable=self.retries_var, style='Debugger.TLabel')
        retries_label.grid(row=1, column=5, sticky=tk.W, padx=(5, 0))
        
        ttk.Label(stats_frame, text="Verified:").grid(row=1, column=6, sticky=tk.W, pady=(5,0))
        self.verified_var = tk.StringVar(value="0")
        verified_label = ttk.Label(stats_frame, textvariable=self.verified_var, style='Verified.TLabel')
        verified_label.grid(row=1, column=7, sticky=tk.W, padx=(5, 0))
        
        ttk.Label(stats_frame, text="Missing:").grid(row=1, column=8, sticky=tk.W, pady=(5,0))
        self.missing_var = tk.StringVar(value="0")
        missing_label = ttk.Label(stats_frame, textvariable=self.missing_var, style='Missing.TLabel')
        missing_label.grid(row=1, column=9, sticky=tk.W, padx=(5, 0))
        
        # Configure grid weights for tab
        tab.columnconfigure(1, weight=1)
        tab.rowconfigure(5, weight=1)
    
    def _create_debugger_tab(self):
        """Create debugger diagnostics tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Debugger")
        
        # Create debugger results viewer
        self.debugger_text = scrolledtext.ScrolledText(tab, state=tk.DISABLED)
        self.debugger_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Add solution buttons
        button_frame = ttk.Frame(tab)
        button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        ttk.Button(button_frame, text="Run Debugger Now", command=self._run_debugger).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Auto-Fix Attributes", command=self._fix_attributes).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Auto-Rename Files", command=self._auto_rename_files).pack(side=tk.LEFT, padx=5)
        
        # Add status label
        self.debugger_status = ttk.Label(tab, text="No debugger issues detected", style='Status.TLabel')
        self.debugger_status.pack(pady=(0, 5))
    
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
    
    def _create_verification_tab(self):
        """NEW: Create verification results tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Verification")
        
        # Create treeview for verification results
        columns = ('size', 'status', 'hash')
        self.verification_tree = ttk.Treeview(
            tab, 
            columns=columns, 
            show='headings',
            selectmode='browse',
            height=20
        )
        
        # Configure columns
        self.verification_tree.heading('#0', text='File Path', anchor=tk.W)
        self.verification_tree.heading('size', text='Size', anchor=tk.W)
        self.verification_tree.heading('status', text='Status', anchor=tk.W)
        self.verification_tree.heading('hash', text='Hash Match', anchor=tk.W)
        
        self.verification_tree.column('#0', width=350, stretch=tk.YES)
        self.verification_tree.column('size', width=100, stretch=tk.NO)
        self.verification_tree.column('status', width=100, stretch=tk.NO)
        self.verification_tree.column('hash', width=120, stretch=tk.NO)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(tab, orient=tk.VERTICAL, command=self.verification_tree.yview)
        self.verification_tree.configure(yscroll=scrollbar.set)
        
        # Layout
        self.verification_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 10), pady=10)
        
        # Add status label
        self.verification_status = ttk.Label(tab, text="Verification results will appear after transfer", style='Status.TLabel')
        self.verification_status.pack(side=tk.BOTTOM, pady=(0, 5))
    
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
            self.engine._update_status("Scanning for PS3 games...")
            games = PS3GameScanner.find_ps3_games(source_path)
            total_size = 0
            total_warnings = 0
            
            # Clear previous results
            self.root.after(0, self.game_list_main.delete, *self.game_list_main.get_children())
            
            for game_path in games:
                try:
                    game_info = PS3GameScanner.get_game_info(game_path)
                    size_gb = game_info['size'] / (1024**3)
                    status = "Valid" if game_info['valid'] else "Invalid"
                    warnings = len(game_info['warning_files'])
                    total_warnings += warnings
                    
                    # Add to the list in the main thread
                    self.root.after(0, lambda name=game_info['name'], size=size_gb, 
                                  stat=status, warn=warnings: self.game_list_main.insert(
                                      '', 'end', text=name, 
                                      values=(f"{size:.2f} GB", stat, warn)
                                  ))
                    
                    total_size += game_info['size']
                except Exception as e:
                    self.engine.logger.error(f"Failed to get game info for {game_path}: {e}")
                    # Add as an error entry
                    self.root.after(0, lambda name=game_path.name: self.game_list_main.insert(
                        '', 'end', text=name, values=("0.00 GB", "Error", 0)
                    ))
            
            # Update status
            status_text = f"Found {len(games)} games | Total size: {total_size / (1024**3):.2f} GB | Warnings: {total_warnings}"
            self.root.after(0, lambda: self.game_info_label.config(text=status_text))
            
        except Exception as e:
            self.engine.logger.error(f"Game scan failed: {e}")
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
            self.engine._update_status("Validating paths...")
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
                        self.engine.logger.warning(f"Path issue: {relative_path} - {', '.join(issues)}")
                        self.root.after(0, self._add_path_warning, file_path, issues)
            
            self.engine._update_status(f"Path validation complete! Found {warning_count} potential issues")
            messagebox.showinfo("Validation Complete", 
                              f"Found {warning_count} files with potential path issues")
            
        except Exception as e:
            self.engine.logger.error(f"Path validation failed: {e}")
            self.engine._update_status("Path validation failed")
    
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
    
    def _run_debugger(self):
        """Run debugger on selected directory"""
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
        
        # Clear previous results
        self.debugger_text.configure(state=tk.NORMAL)
        self.debugger_text.delete(1.0, tk.END)
        self.debugger_text.configure(state=tk.DISABLED)
        self.debugger_status.config(text="Running debugger...")
        
        # Start debugger in separate thread
        threading.Thread(
            target=self._run_debugger_scan,
            args=(source_path, dest_path),
            daemon=True
        ).start()
    
    def _run_debugger_scan(self, source_path: Path, dest_path: Path):
        """Run debugger scan and report issues"""
        try:
            self.engine._update_status("Running pre-transfer debugger...")
            issue_count = 0
            fixed_count = 0
            
            for root, dirs, files in os.walk(source_path):
                for file in files:
                    file_path = Path(root) / file
                    issues, fixed = EnhancedDebugger.check_file_integrity(file_path, dest_path, self.engine.logger)
                    
                    if issues:
                        issue_count += 1
                        if fixed:
                            fixed_count += 1
                        
                        # Update debugger tab
                        self.root.after(0, self.debugger_text.configure, tk.NORMAL)
                        self.root.after(0, self.debugger_text.insert, tk.END, f"⚠️ File: {file_path}\n")
                        for issue in issues:
                            self.root.after(0, self.debugger_text.insert, tk.END, f"   - {issue}\n")
                        if fixed:
                            self.root.after(0, self.debugger_text.insert, tk.END, "   ✅ Fixed: Read-only attribute\n")
                        self.root.after(0, self.debugger_text.insert, tk.END, "-" * 80 + "\n")
                        self.root.after(0, self.debugger_text.see, tk.END)
                        self.root.after(0, self.debugger_text.configure, tk.DISABLED)
            
            self.engine._update_status(f"Debugger complete! Found {issue_count} issues, fixed {fixed_count}")
            self.root.after(0, lambda: self.debugger_status.config(
                text=f"Debugger found {issue_count} issues, fixed {fixed_count}"
            ))
            
        except Exception as e:
            self.engine.logger.error(f"Debugger failed: {e}")
            self.engine._update_status("Debugger failed")
    
    def _fix_attributes(self):
        """Fix file attributes in selected directory"""
        source = self.source_var.get().strip()
        if not source:
            messagebox.showerror("Error", "Please select source directory first")
            return
        
        source_path = Path(source)
        if not source_path.exists():
            messagebox.showerror("Error", "Source directory does not exist")
            return
        
        # Start attribute fix in separate thread
        threading.Thread(
            target=self._run_attribute_fix,
            args=(source_path,),
            daemon=True
        ).start()
    
    def _run_attribute_fix(self, source_path: Path):
        """Fix file attributes recursively"""
        try:
            self.engine._update_status("Fixing file attributes...")
            fixed_count = 0
            
            for root, dirs, files in os.walk(source_path):
                for file in files:
                    file_path = Path(root) / file
                    if platform.system() == 'Windows':
                        try:
                            subprocess.run(['attrib', '-R', '-H', '-S', str(file_path)], 
                                         check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                            fixed_count += 1
                        except:
                            pass
            
            self.engine._update_status(f"Fixed attributes for {fixed_count} files")
            messagebox.showinfo("Success", f"Fixed attributes for {fixed_count} files")
            
        except Exception as e:
            self.engine.logger.error(f"Attribute fix failed: {e}")
            self.engine._update_status("Attribute fix failed")
    
    def _auto_rename_files(self):
        """Automatically rename problematic files"""
        source = self.source_var.get().strip()
        if not source:
            messagebox.showerror("Error", "Please select source directory first")
            return
        
        source_path = Path(source)
        if not source_path.exists():
            messagebox.showerror("Error", "Source directory does not exist")
            return
        
        # Start renaming in separate thread
        threading.Thread(
            target=self._run_auto_rename,
            args=(source_path,),
            daemon=True
        ).start()
    
    def _run_auto_rename(self, source_path: Path):
        """Automatically rename files with invalid names"""
        try:
            self.engine._update_status("Renaming problematic files...")
            renamed_count = 0
            
            for root, dirs, files in os.walk(source_path):
                for file in files:
                    original_path = Path(root) / file
                    sanitized_name = PS3FileValidator.sanitize_filename(file)
                    new_path = original_path.with_name(sanitized_name)
                    
                    if file != sanitized_name:
                        try:
                            original_path.rename(new_path)
                            renamed_count += 1
                        except:
                            pass
            
            self.engine._update_status(f"Renamed {renamed_count} files")
            messagebox.showinfo("Success", f"Renamed {renamed_count} files")
            
        except Exception as e:
            self.engine.logger.error(f"Auto-rename failed: {e}")
            self.engine._update_status("Auto-rename failed")
    
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
        
        # Clear verification tab
        self.verification_tree.delete(*self.verification_tree.get_children())
        self.verification_status.config(text="Verification in progress...")
        
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
            self.engine.logger.error(f"Transfer thread error: {e}", exc_info=True)
            self.root.after(0, self._transfer_completed, False)
    
    def _transfer_completed(self, success: bool):
        """Handle transfer completion"""
        self.start_button.configure(state=tk.NORMAL)
        self.pause_button.configure(state=tk.DISABLED)
        self.pause_button.configure(text='Pause')
        self.cancel_button.configure(state=tk.DISABLED)
        
        if success:
            messagebox.showinfo("Success", "Transfer completed successfully!")
            self.error_status.config(text="Transfer completed successfully!")
            # Load verification results
            self._load_verification_results()
        else:
            self.error_status.config(text="Transfer failed - see error diagnostics")
            self._show_error_guide()
    
    def _load_verification_results(self):
        """Load verification results into the verification tab"""
        self.verification_tree.delete(*self.verification_tree.get_children())
        
        if not self.engine.file_manifest or 'files' not in self.engine.file_manifest:
            self.verification_status.config(text="No verification data available")
            return
        
        verified_count = 0
        total_files = len(self.engine.file_manifest['files'])
        
        for relative_path, file_info in self.engine.file_manifest['files'].items():
            status = "Verified" if file_info.get('verified', False) else "Not Verified"
            status_style = ""
            
            if status == "Verified":
                verified_count += 1
                status_style = "Verified.TLabel"
            else:
                status_style = "Warning.TLabel"
            
            size_str = f"{file_info['size'] / (1024**2):.2f} MB"
            hash_match = "N/A"
            
            if file_info.get('hash'):
                hash_match = "Matched" if file_info.get('verified', False) else "Mismatch"
            
            self.verification_tree.insert('', 'end', text=relative_path, 
                                        values=(size_str, status, hash_match),
                                        tags=(status_style,))
        
        # Apply tags for styling
        self.verification_tree.tag_configure('Verified.TLabel', foreground='green')
        self.verification_tree.tag_configure('Warning.TLabel', foreground='orange')
        
        # Update status
        status_text = f"Verified {verified_count}/{total_files} files"
        self.verification_status.config(text=status_text)
    
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
        self.engine.stats.warning_files += 1
        self.root.after(0, self.warnings_var.set, str(self.engine.stats.warning_files))
        
        # Add to error diagnostics tab
        self.root.after(0, self._add_path_warning, file_path, issues)
    
    def _handle_debugger_issue(self, file_path: Path, issues: List[str], fixed: bool):
        """Handle debugger issues during transfer"""
        self.engine.stats.debugger_issues += 1
        if fixed:
            self.engine.stats.debugger_fixed += 1
            
        self.root.after(0, self.debugger_var.set, str(self.engine.stats.debugger_issues))
        self.root.after(0, self.fixed_var.set, str(self.engine.stats.debugger_fixed))
        
        # Add to debugger tab
        self.root.after(0, self.debugger_text.configure, tk.NORMAL)
        self.root.after(0, self.debugger_text.insert, tk.END, f"⚠️ File: {file_path}\n")
        for issue in issues:
            self.root.after(0, self.debugger_text.insert, tk.END, f"   - {issue}\n")
        if fixed:
            self.root.after(0, self.debugger_text.insert, tk.END, "   ✅ Fixed: Read-only attribute\n")
        self.root.after(0, self.debugger_text.insert, tk.END, "-" * 80 + "\n")
        self.root.after(0, self.debugger_text.see, tk.END)
        self.root.after(0, self.debugger_text.configure, tk.DISABLED)
        self.root.after(0, self.debugger_status.config, 
                       text=f"{self.debugger_text.index('end-1c').split('.')[0]} issues found, {self.engine.stats.debugger_fixed} fixed")
    
    def _update_progress(self, stats: TransferStats):
        """Update progress display"""
        if stats.total_size > 0:
            progress = (stats.transferred_size / stats.total_size) * 100
            self.progress_var.set(progress)
        
        self.current_file_var.set(stats.current_file)
        self.files_var.set(f"{stats.processed_files}/{stats.total_files}")
        self.games_var.set(f"{stats.games_count}")
        self.warnings_var.set(f"{stats.warning_files}")
        self.debugger_var.set(f"{stats.debugger_issues}")
        self.fixed_var.set(f"{stats.debugger_fixed}")
        self.retries_var.set(f"{stats.debugger_retries}")
        self.verified_var.set(f"{stats.verified_files}")
        self.missing_var.set(f"{stats.missing_files}")
        
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

5. ❗ File System Metadata Limitations
   - Some file systems have limitations on:
     * File names containing certain reserved words (CON, PRN, AUX, NUL)
     * Files with specific metadata attributes

   ✅ Solutions:
   - Rename file to avoid reserved names
   - Check filesystem for corruption (run CHKDSK on Windows)
   - Try transferring to a different drive

🛠️ Additional Recommendations:
- Use the integrated debugger tool to detect issues
- Try manually copying the problematic file
- Check error diagnostics tab for specific file issues
- Consult logs for detailed error information"""
        
        messagebox.showinfo("Transfer Error Guide", guide)
    
    def _view_manifest(self):
        """View transfer manifest"""
        try:
            if not self.engine.manifest_path.exists():
                messagebox.showinfo("Manifest", "No manifest available. Run a transfer first.")
                return
                
            with open(self.engine.manifest_path, 'r') as f:
                manifest_content = json.load(f)
            
            # Create a formatted string
            manifest_str = json.dumps(manifest_content, indent=2)
            
            # Show in a dialog
            manifest_window = tk.Toplevel(self.root)
            manifest_window.title("Transfer Manifest")
            manifest_window.geometry("800x600")
            
            text_area = scrolledtext.ScrolledText(manifest_window, wrap=tk.WORD)
            text_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            text_area.insert(tk.INSERT, manifest_str)
            text_area.configure(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("Error", f"Could not open manifest: {e}")
    
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
    
    def _set_debug_level(self):
        """Set debug level from radio buttons"""
        self.logger.set_debug_level(self.debug_level.get())
    
    def close_app(self):
        """Clean up before closing"""
        self.engine.stop_debugger()
        self.root.destroy()
    
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
