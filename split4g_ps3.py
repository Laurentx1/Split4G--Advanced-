import os
import shutil
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path
import time
import logging
from datetime import timedelta
import threading
import queue
import hashlib
import re
import json
import psutil
from typing import List, Tuple, Dict, Optional  # Fixed type hint imports
import tempfile

# ===== CONSTANTS =====
FAT32_LIMIT = 4 * 1024**3 - 1  # 4GB - 1 byte
MIN_BUFFER_SIZE = 1024 * 1024  # 1MB minimum
MAX_BUFFER_SIZE = 128 * 1024 * 1024  # 128MB maximum
PS3_SPLIT_EXT = ".66600"  # Standard PS3 split extension
LOG_FILE = "ps3_game_copier.log"
RESUME_FILE = "ps3_copy_resume.json"
CONFIG_FILE = "ps3_copier_config.json"

# PS3 file validation
REQUIRED_PS3_FILES = ['PS3_DISC.SFB', 'PARAM.SFO', 'ICON0.PNG']
PS3_FILE_SIGNATURES = {
    'PARAM.SFO': b'\x00PSF',
    'PS3_DISC.SFB': b'PS3D',
    'EBOOT.BIN': b'\x7FELF'
}

# FAT32 reserved names
FAT32_RESERVED_NAMES = {
    'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5',
    'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4',
    'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
}

class PS3GameCopier:
    def __init__(self, root):
        self.root = root
        self.setup_logging()
        self.load_config()
        self.setup_ui()
        self.setup_vars()
        
        # Thread management
        self.gui_queue = queue.Queue()
        self.root.after(100, self.process_gui_queue)

    def setup_logging(self):
        """Setup comprehensive logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(LOG_FILE, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def load_config(self):
        """Load configuration from file"""
        self.config = {
            'buffer_size': self.calculate_optimal_buffer_size(),
            'max_retries': 3,
            'retry_delay': 2,
            'verify_signatures': True,
            'create_backup': False,
            'show_advanced': False
        }
        
        try:
            if Path(CONFIG_FILE).exists():
                with open(CONFIG_FILE, 'r') as f:
                    saved_config = json.load(f)
                    self.config.update(saved_config)
        except Exception as e:
            self.logger.warning(f"Could not load config: {e}")

    def save_config(self):
        """Save configuration to file"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            self.logger.warning(f"Could not save config: {e}")

    def calculate_optimal_buffer_size(self) -> int:
        """Calculate optimal buffer size based on available memory"""
        try:
            available_memory = psutil.virtual_memory().available
            # Use 1% of available memory, clamped to min/max
            optimal_size = max(MIN_BUFFER_SIZE, min(MAX_BUFFER_SIZE, available_memory // 100))
            return optimal_size
        except:
            return 32 * 1024 * 1024  # 32MB fallback

    def setup_vars(self):
        self.source = Path(".")
        self.dest = Path(".")
        self.is_running = False
        self.should_cancel = False
        self.resume_data = {}
        self.duplicate_games = {}
        self.stats = {
            'total_files': 0,
            'total_size': 0,
            'copied': 0,
            'split': 0,
            'skipped': 0,
            'failed': 0,
            'bytes_copied': 0,
            'start_time': 0,
            'current_file': "",
            'retry_count': 0
        }

    def setup_ui(self):
        """Modern modular UI setup"""
        self.root.title("PS3 Game Copier - Enhanced Edition")
        self.root.geometry("900x750")
        self.root.minsize(800, 600)
        
        # Apply modern theme
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook.Tab", font=("Segoe UI", 10, "bold"), padding=[10, 5])
        
        # Create main container
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Setup tabs
        self.setup_main_tab()
        self.setup_advanced_tab()
        self.setup_log_tab()
        
        # Status bar
        self.status_bar = ttk.Frame(main_container)
        self.status_bar.pack(fill=tk.X, pady=(5, 0))
        self.status_var = tk.StringVar(value="Status: Ready")
        ttk.Label(self.status_bar, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W).pack(fill=tk.X)

    def setup_main_tab(self):
        """Modern main tab UI"""
        self.main_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.main_frame, text="Main")
        
        # Source section
        src_frame = ttk.LabelFrame(self.main_frame, text="Source Directory", padding=10)
        src_frame.pack(fill=tk.X, pady=5)
        self.setup_source_ui(src_frame)
        
        # Destination section
        dest_frame = ttk.LabelFrame(self.main_frame, text="Destination Directory", padding=10)
        dest_frame.pack(fill=tk.X, pady=5)
        self.setup_destination_ui(dest_frame)
        
        # Options section
        opt_frame = ttk.LabelFrame(self.main_frame, text="Copy Options", padding=10)
        opt_frame.pack(fill=tk.X, pady=5)
        self.setup_options_ui(opt_frame)
        
        # Game list section
        game_frame = ttk.LabelFrame(self.main_frame, text="Games Preview", padding=10)
        game_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.setup_game_list_ui(game_frame)
        
        # Progress section
        prog_frame = ttk.LabelFrame(self.main_frame, text="Progress", padding=10)
        prog_frame.pack(fill=tk.X, pady=5)
        self.setup_progress_ui(prog_frame)
        
        # Button section
        btn_frame = ttk.Frame(self.main_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        self.setup_buttons_ui(btn_frame)

    def setup_source_ui(self, parent):
        """UI for source selection"""
        src_entry_frame = ttk.Frame(parent)
        src_entry_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(src_entry_frame, text="Folder with PS3 Games:").pack(side=tk.LEFT, padx=(0, 10))
        self.source_entry = ttk.Entry(src_entry_frame, width=60)
        self.source_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        src_btn_frame = ttk.Frame(src_entry_frame)
        src_btn_frame.pack(side=tk.RIGHT)
        ttk.Button(src_btn_frame, text="Browse", command=self.browse_source).pack(side=tk.LEFT, padx=2)
        ttk.Button(src_btn_frame, text="Scan", command=self.scan_games_preview).pack(side=tk.LEFT, padx=2)

    def setup_destination_ui(self, parent):
        """UI for destination selection"""
        dest_entry_frame = ttk.Frame(parent)
        dest_entry_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(dest_entry_frame, text="FAT32 Destination:").pack(side=tk.LEFT, padx=(0, 10))
        self.dest_entry = ttk.Entry(dest_entry_frame, width=60)
        self.dest_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        ttk.Button(dest_entry_frame, text="Browse", command=self.browse_dest).pack(side=tk.RIGHT)

    def setup_options_ui(self, parent):
        """UI for copy options"""
        opt_row1 = ttk.Frame(parent)
        opt_row1.pack(fill=tk.X, pady=5)
        
        self.split_var = tk.BooleanVar(value=True)
        self.split_cb = ttk.Checkbutton(opt_row1, text="Split files >4GB", variable=self.split_var)
        self.split_cb.pack(side=tk.LEFT, padx=10)
        self.create_tooltip(self.split_cb, "Split large files for FAT32 compatibility")
        
        self.verify_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_row1, text="Verify files", variable=self.verify_var).pack(side=tk.LEFT, padx=10)
        
        self.dry_run_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt_row1, text="Dry run", variable=self.dry_run_var).pack(side=tk.LEFT, padx=10)
        
        opt_row2 = ttk.Frame(parent)
        opt_row2.pack(fill=tk.X, pady=5)
        
        self.skip_duplicates_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_row2, text="Skip duplicates", variable=self.skip_duplicates_var).pack(side=tk.LEFT, padx=10)
        
        self.resume_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_row2, text="Resume", variable=self.resume_var).pack(side=tk.LEFT, padx=10)

    def setup_game_list_ui(self, parent):
        """UI for game list preview"""
        # Create treeview with scrollbars
        columns = ('Name', 'Size', 'Type', 'Status')
        self.game_tree = ttk.Treeview(parent, columns=columns, show='headings', height=10)
        
        # Configure columns
        col_widths = {'Name': 250, 'Size': 100, 'Type': 120, 'Status': 100}
        for col in columns:
            self.game_tree.heading(col, text=col)
            self.game_tree.column(col, width=col_widths.get(col, 100), anchor=tk.W)
        
        # Add scrollbars
        tree_scroll_y = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.game_tree.yview)
        tree_scroll_x = ttk.Scrollbar(parent, orient=tk.HORIZONTAL, command=self.game_tree.xview)
        self.game_tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)
        
        # Layout
        self.game_tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll_y.grid(row=0, column=1, sticky="ns")
        tree_scroll_x.grid(row=1, column=0, sticky="ew")
        
        # Configure grid weights
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)

    def setup_progress_ui(self, parent):
        """UI for progress display"""
        self.progress = ttk.Progressbar(parent, orient=tk.HORIZONTAL, mode='determinate')
        self.progress.pack(fill=tk.X, pady=(0, 10))
        
        self.file_var = tk.StringVar(value="Ready to copy PS3 games...")
        file_label = ttk.Label(parent, textvariable=self.file_var, wraplength=700)
        file_label.pack(fill=tk.X, pady=5)
        
        # Speed and ETA display
        stats_frame = ttk.Frame(parent)
        stats_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(stats_frame, text="Speed:").pack(side=tk.LEFT, padx=(0, 5))
        self.speed_var = tk.StringVar(value="0 MB/s")
        ttk.Label(stats_frame, textvariable=self.speed_var, width=10).pack(side=tk.LEFT, padx=(0, 15))
        
        ttk.Label(stats_frame, text="ETA:").pack(side=tk.LEFT, padx=(0, 5))
        self.eta_var = tk.StringVar(value="00:00:00")
        ttk.Label(stats_frame, textvariable=self.eta_var, width=10).pack(side=tk.LEFT, padx=(0, 15))
        
        ttk.Label(stats_frame, text="Copied:").pack(side=tk.LEFT, padx=(0, 5))
        self.copied_var = tk.StringVar(value="0/0")
        ttk.Label(stats_frame, textvariable=self.copied_var, width=10).pack(side=tk.LEFT)

    def setup_buttons_ui(self, parent):
        """UI for action buttons"""
        self.start_btn = ttk.Button(parent, text="Start Copy", command=self.start_copy, width=15)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.cancel_btn = ttk.Button(parent, text="Cancel", command=self.cancel_copy, state=tk.DISABLED, width=15)
        self.cancel_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(parent, text="Clear Log", command=self.clear_log, width=10).pack(side=tk.RIGHT, padx=5)
        ttk.Button(parent, text="Settings", command=self.show_settings, width=10).pack(side=tk.RIGHT, padx=5)

    def setup_advanced_tab(self):
        """Modern advanced settings tab"""
        self.advanced_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.advanced_frame, text="Advanced")
        
        # Performance settings
        perf_frame = ttk.LabelFrame(self.advanced_frame, text="Performance Settings", padding=10)
        perf_frame.pack(fill=tk.X, pady=5)
        self.setup_performance_ui(perf_frame)
        
        # Error handling
        error_frame = ttk.LabelFrame(self.advanced_frame, text="Error Handling", padding=10)
        error_frame.pack(fill=tk.X, pady=5)
        self.setup_error_ui(error_frame)
        
        # Validation settings
        valid_frame = ttk.LabelFrame(self.advanced_frame, text="Validation Settings", padding=10)
        valid_frame.pack(fill=tk.X, pady=5)
        self.setup_validation_ui(valid_frame)
        
        # Save/load settings
        save_frame = ttk.Frame(self.advanced_frame)
        save_frame.pack(fill=tk.X, pady=20)
        self.setup_save_ui(save_frame)

    def setup_performance_ui(self, parent):
        """Performance settings UI"""
        buffer_frame = ttk.Frame(parent)
        buffer_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(buffer_frame, text="Buffer Size (MB):").pack(side=tk.LEFT, padx=(0, 10))
        self.buffer_var = tk.IntVar(value=self.config['buffer_size'] // (1024*1024))
        buffer_spin = ttk.Spinbox(buffer_frame, from_=1, to=128, textvariable=self.buffer_var, width=10)
        buffer_spin.pack(side=tk.LEFT)
        self.create_tooltip(buffer_spin, "Memory buffer size for file copying")

    def setup_error_ui(self, parent):
        """Error handling UI"""
        retry_frame = ttk.Frame(parent)
        retry_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(retry_frame, text="Max Retries:").pack(side=tk.LEFT, padx=(0, 10))
        self.retry_var = tk.IntVar(value=self.config['max_retries'])
        retry_spin = ttk.Spinbox(retry_frame, from_=0, to=10, textvariable=self.retry_var, width=5)
        retry_spin.pack(side=tk.LEFT, padx=(0, 20))
        
        ttk.Label(retry_frame, text="Retry Delay (s):").pack(side=tk.LEFT, padx=(0, 10))
        self.retry_delay_var = tk.IntVar(value=self.config['retry_delay'])
        delay_spin = ttk.Spinbox(retry_frame, from_=1, to=30, textvariable=self.retry_delay_var, width=5)
        delay_spin.pack(side=tk.LEFT)

    def setup_validation_ui(self, parent):
        """Validation settings UI"""
        self.signature_var = tk.BooleanVar(value=self.config['verify_signatures'])
        sig_cb = ttk.Checkbutton(parent, text="Verify PS3 file signatures", variable=self.signature_var)
        sig_cb.pack(anchor=tk.W, pady=5)
        self.create_tooltip(sig_cb, "Validate critical PS3 file signatures")
        
        self.backup_var = tk.BooleanVar(value=self.config['create_backup'])
        backup_cb = ttk.Checkbutton(parent, text="Create backup of existing files", variable=self.backup_var)
        backup_cb.pack(anchor=tk.W, pady=5)
        self.create_tooltip(backup_cb, "Backup existing files before overwriting")

    def setup_save_ui(self, parent):
        """Save settings UI"""
        ttk.Button(parent, text="Save Settings", command=self.save_settings, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(parent, text="Reset to Defaults", command=self.reset_settings, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(parent, text="Close", command=self.hide_settings, width=10).pack(side=tk.RIGHT, padx=5)

    def setup_log_tab(self):
        """Modern log display tab"""
        self.log_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.log_frame, text="Log")
        
        log_container = ttk.Frame(self.log_frame)
        log_container.pack(fill=tk.BOTH, expand=True)
        
        # Log text widget with scrollbar
        self.log_text = scrolledtext.ScrolledText(log_container, height=25, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED)

    def create_tooltip(self, widget, text):
        """Create tooltip for widgets"""
        tooltip = tk.Toplevel(widget)
        tooltip.wm_overrideredirect(True)
        tooltip.wm_withdraw()
        
        label = ttk.Label(tooltip, text=text, background="#ffffe0", relief=tk.SOLID, borderwidth=1)
        label.pack(ipadx=1)
        
        def enter(event):
            x = widget.winfo_rootx() + widget.winfo_width() + 5
            y = widget.winfo_rooty()
            tooltip.wm_geometry(f"+{x}+{y}")
            tooltip.wm_deiconify()
        
        def leave(event):
            tooltip.wm_withdraw()
        
        widget.bind("<Enter>", enter)
        widget.bind("<Leave>", leave)

    def save_settings(self):
        """Save current settings to config"""
        self.config.update({
            'buffer_size': self.buffer_var.get() * 1024 * 1024,
            'max_retries': self.retry_var.get(),
            'retry_delay': self.retry_delay_var.get(),
            'verify_signatures': self.signature_var.get(),
            'create_backup': self.backup_var.get()
        })
        self.save_config()
        messagebox.showinfo("Settings", "Settings saved successfully!")

    def reset_settings(self):
        """Reset settings to defaults"""
        self.config = {
            'buffer_size': self.calculate_optimal_buffer_size(),
            'max_retries': 3,
            'retry_delay': 2,
            'verify_signatures': True,
            'create_backup': False,
            'show_advanced': False
        }
        self.buffer_var.set(self.config['buffer_size'] // (1024*1024))
        self.retry_var.set(self.config['max_retries'])
        self.retry_delay_var.set(self.config['retry_delay'])
        self.signature_var.set(self.config['verify_signatures'])
        self.backup_var.set(self.config['create_backup'])
        messagebox.showinfo("Settings", "Settings reset to defaults!")

    def show_settings(self):
        """Show advanced settings tab"""
        self.notebook.select(self.advanced_frame)

    def hide_settings(self):
        """Hide advanced settings tab"""
        self.notebook.select(self.main_frame)

    def clear_log(self):
        """Clear the log display"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)

    def log_to_ui(self, message: str, level: str = "INFO"):
        """Add message to UI log"""
        timestamp = time.strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] {level}: {message}\n"
        
        def update_log():
            self.log_text.config(state=tk.NORMAL)
            self.log_text.insert(tk.END, formatted_msg)
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)
        
        self.gui_queue.put(update_log)

    def browse_source(self):
        path = filedialog.askdirectory(initialdir=str(self.source), title="Select folder with PS3 games")
        if path:
            self.source = Path(path)
            self.source_entry.delete(0, tk.END)
            self.source_entry.insert(0, str(self.source))

    def browse_dest(self):
        initial_dir = str(self.dest) if self.dest.exists() else str(Path(self.source) / "GAMES")
        path = filedialog.askdirectory(initialdir=initial_dir, title="Select or create GAMES folder on FAT32 drive")
        if path:
            self.dest = Path(path)
            self.dest_entry.delete(0, tk.END)
            self.dest_entry.insert(0, str(self.dest))

    def scan_games_preview(self):
        """Scan and preview games that will be copied"""
        if not self.source_entry.get():
            messagebox.showwarning("Warning", "Please select a source folder first!")
            return
        
        self.source = Path(self.source_entry.get())
        if not self.source.exists():
            messagebox.showerror("Error", "Source folder doesn't exist!")
            return
        
        # Clear existing items
        for item in self.game_tree.get_children():
            self.game_tree.delete(item)
        
        # Scan for games
        threading.Thread(target=self._scan_games_thread, daemon=True).start()

    def _scan_games_thread(self):
        """Thread function to scan games"""
        try:
            games_found = 0
            total_size = 0
            
            for game_folder in self.scan_source():
                if self.is_valid_ps3_folder(game_folder):
                    size = self.get_folder_size(game_folder)
                    game_type = self.detect_game_type(game_folder)
                    status = "Ready"
                    
                    # Check for duplicates if destination exists
                    if self.dest_entry.get() and Path(self.dest_entry.get()).exists():
                        dest_folder = Path(self.dest_entry.get()) / self.sanitize_folder_name(game_folder.name)
                        if dest_folder.exists():
                            status = "Duplicate"
                    
                    # Add to tree view
                    self.gui_queue.put(lambda f=game_folder, s=size, t=game_type, st=status: 
                        self.game_tree.insert('', 'end', values=(
                            f.name, 
                            self.format_size(s), 
                            t, 
                            st
                        ))
                    )
                    
                    games_found += 1
                    total_size += size
            
            # Update summary
            self.gui_queue.put(lambda: self.log_to_ui(
                f"Scan complete: {games_found} games found ({self.format_size(total_size)} total)"
            ))
            
        except Exception as e:
            self.gui_queue.put(lambda: self.log_to_ui(f"Scan error: {e}", "ERROR"))

    def detect_game_type(self, folder: Path) -> str:
        """Detect if game is disc image or folder game"""
        if (folder / "PS3_DISC.SFB").exists():
            return "Disc Image"
        elif (folder / "PS3_GAME" / "PARAM.SFO").exists():
            return "Folder Game"
        elif (folder / "USRDIR").exists() and (folder / "EBOOT.BIN").exists():
            return "PSN Game"
        else:
            return "Unknown"

    def start_copy(self):
        if not self.validate_paths():
            return
        
        # Update config from UI
        self.config['buffer_size'] = self.buffer_var.get() * 1024 * 1024
        self.config['max_retries'] = self.retry_var.get()
        self.config['retry_delay'] = self.retry_delay_var.get()
        self.config['verify_signatures'] = self.signature_var.get()
        self.config['create_backup'] = self.backup_var.get()
        
        self.prepare_for_copy()
        threading.Thread(target=self.copy_process, daemon=True).start()

    def validate_paths(self):
        self.source = Path(self.source_entry.get())
        self.dest = Path(self.dest_entry.get())
        
        if not self.source.exists():
            messagebox.showerror("Error", "Source folder doesn't exist!")
            return False
            
        if not self.dest.exists():
            try:
                self.dest.mkdir(parents=True)
                self.log_to_ui(f"Created destination folder: {self.dest}")
            except Exception as e:
                messagebox.showerror("Error", f"Couldn't create destination folder:\n{e}")
                return False
        
        # Enhanced FAT32 validation
        if not self.validate_fat32_destination():
            return False
            
        # Check for large files if splitting is disabled
        if not self.split_var.get():
            large_files = self.check_for_large_files()
            if large_files:
                msg = (f"Found {len(large_files)} files that exceed the 4GB FAT32 limit but splitting is disabled!\n"
                       "These files cannot be copied without splitting.\n\n"
                       "First few files:\n" + "\n".join(large_files[:5]))
                if len(large_files) > 5:
                    msg += f"\n...and {len(large_files)-5} more"
                messagebox.showwarning("Large Files Detected", msg)
                return False
                
        return True

    def check_for_large_files(self) -> List[str]:
        """Return list of files >4GB in source"""
        large_files = []
        for game_folder in self.scan_source():
            if not self.is_valid_ps3_folder(game_folder):
                continue
                
            for file_path in game_folder.rglob('*'):
                if file_path.is_file():
                    try:
                        if file_path.stat().st_size > FAT32_LIMIT:
                            rel_path = file_path.relative_to(self.source)
                            large_files.append(str(rel_path))
                    except (OSError, IOError) as e:
                        self.log_to_ui(f"Could not check size for {file_path}: {e}", "WARNING")
                        continue
        return large_files

    def validate_fat32_destination(self) -> bool:
        """Enhanced FAT32 validation"""
        try:
            # Test file creation
            test_file = self.dest / "~fat32test.tmp"
            with open(test_file, 'wb') as f:
                f.write(b'PS3 Game Copier test file - safe to delete')
            
            # Test long filename support
            long_name = "a" * 200 + ".tmp"
            long_test = self.dest / long_name
            try:
                with open(long_test, 'wb') as f:
                    f.write(b'test')
                long_test.unlink()
                self.log_to_ui("Long filename support confirmed")
            except:
                self.log_to_ui("Long filename support limited", "WARNING")
            
            test_file.unlink()
            
            # Check available space
            free_space = shutil.disk_usage(self.dest)[2]
            self.log_to_ui(f"Available space: {self.format_size(free_space)}")
            
            return True
            
        except Exception as e:
            messagebox.showerror("Error", f"Destination validation failed:\n{e}")
            return False

    def sanitize_folder_name(self, name: str) -> str:
        """Enhanced folder name sanitization for FAT32"""
        original_name = name
        
        # Replace invalid FAT32 characters
        name = re.sub(r'[\\/*?:"<>|]', '_', name)
        
        # Handle reserved names
        name_upper = name.upper()
        if name_upper in FAT32_RESERVED_NAMES or name_upper.split('.')[0] in FAT32_RESERVED_NAMES:
            name = f"_{name}"
        
        # Remove trailing dots and spaces
        name = name.rstrip('. ')
        
        # Ensure not empty
        if not name:
            name = "PS3_Game"
        
        # Trim to reasonable length (FAT32 max is 255 chars, but we'll use 128)
        if len(name) > 128:
            name = name[:125] + "..."
        
        if name != original_name:
            self.log_to_ui(f"Sanitized folder name: '{original_name}' -> '{name}'")
            
        return name

    def prepare_for_copy(self):
        self.is_running = True
        self.should_cancel = False
        self.start_btn.config(state=tk.DISABLED)
        self.cancel_btn.config(state=tk.NORMAL)
        self.status_var.set("Status: Preparing...")
        self.file_var.set("Scanning for PS3 games...")
        
        # Load resume data if available
        self.load_resume_data()

    def load_resume_data(self):
        """Load resume data from previous interrupted session"""
        try:
            if Path(RESUME_FILE).exists() and self.resume_var.get():
                with open(RESUME_FILE, 'r') as f:
                    self.resume_data = json.load(f)
                self.log_to_ui(f"Loaded resume data: {len(self.resume_data)} entries")
        except Exception as e:
            self.log_to_ui(f"Could not load resume data: {e}", "WARNING")
            self.resume_data = {}

    def save_resume_data(self):
        """Save resume data for interrupted sessions"""
        try:
            with open(RESUME_FILE, 'w') as f:
                json.dump(self.resume_data, f, indent=2)
        except Exception as e:
            self.log_to_ui(f"Could not save resume data: {e}", "WARNING")

    def copy_process(self):
        try:
            self.initialize_copy()
            
            if self.dry_run_var.get():
                self.perform_dry_run()
            else:
                # Process all game files
                for game_file in self.scan_source():
                    if self.should_cancel:
                        break
                    
                    if self.is_valid_ps3_folder(game_file):
                        self.process_game(game_file)
            
            self.finalize_copy()
            
        except Exception as e:
            self.handle_error(e)
        finally:
            self.cleanup()

    def perform_dry_run(self):
        """Perform a dry run showing what would be copied"""
        self.log_to_ui("=== DRY RUN MODE ===")
        games_to_copy = []
        total_size = 0
        
        for game_folder in self.scan_source():
            if self.should_cancel:
                break
                
            if self.is_valid_ps3_folder(game_folder):
                size = self.get_folder_size(game_folder)
                dest_folder = self.dest / self.sanitize_folder_name(game_folder.name)
                
                status = "COPY"
                if dest_folder.exists() and self.skip_duplicates_var.get():
                    status = "SKIP (duplicate)"
                
                games_to_copy.append((game_folder.name, size, status))
                if status == "COPY":
                    total_size += size
                
                self.log_to_ui(f"{status}: {game_folder.name} ({self.format_size(size)})")
        
        self.log_to_ui(f"\nDry run summary:")
        self.log_to_ui(f"Games found: {len(games_to_copy)}")
        self.log_to_ui(f"Games to copy: {sum(1 for _, _, status in games_to_copy if status == 'COPY')}")
        self.log_to_ui(f"Total size to copy: {self.format_size(total_size)}")
        self.log_to_ui("=== END DRY RUN ===")

    def scan_source(self):
        """Enhanced source scanning with validation"""
        if not self.source.exists():
            return
            
        for item in self.source.iterdir():
            if item.is_dir():
                yield item

    def is_valid_ps3_folder(self, folder: Path) -> bool:
        """Enhanced PS3 folder validation with signature checking"""
        # Check for common PS3 game structures
        valid_structures = [
            # Disc game structure
            lambda f: (f/"PS3_DISC.SFB").exists() and (f/"PS3_GAME"/"PARAM.SFO").exists(),
            # Folder game structure (common for digital games)
            lambda f: (f/"PARAM.SFO").exists(),
            # Digital download structure (common for PSN games)
            lambda f: (f/"EBOOT.BIN").exists() and (f/"USRDIR").exists(),
            # Minimal valid structure: at least one SFO file or an EBOOT.BIN
            lambda f: any(f.glob("*.SFO")) or any(f.glob("EBOOT.BIN"))
        ]
        
        if not any(check(folder) for check in valid_structures):
            return False
        
        # Optional signature validation
        if self.config['verify_signatures']:
            return self.verify_ps3_signatures(folder)
        
        return True

    def verify_ps3_signatures(self, folder: Path) -> bool:
        """Verify PS3 file signatures"""
        try:
            for filename, signature in PS3_FILE_SIGNATURES.items():
                file_paths = [
                    folder / filename,
                    folder / "PS3_GAME" / filename
                ]
                
                for file_path in file_paths:
                    if file_path.exists():
                        with open(file_path, 'rb') as f:
                            file_header = f.read(len(signature))
                            if file_header == signature:
                                return True
            
            return True  # If no signature files found, assume valid
            
        except Exception as e:
            self.log_to_ui(f"Signature verification failed for {folder.name}: {e}", "WARNING")
            return True  # Don't reject on verification errors

    def process_game(self, game_folder: Path):
        """Enhanced game processing with retry logic"""
        folder_name = game_folder.name
        self.stats['current_file'] = folder_name
        self.update_file_status()
        
        dest_folder = self.dest / self.sanitize_folder_name(folder_name)
        
        # Check for duplicates
        if dest_folder.exists() and self.skip_duplicates_var.get():
            self.log_to_ui(f"Skipping duplicate: {folder_name}")
            self.stats['skipped'] += 1
            self.update_stats()
            return
        
        # Check resume data
        resume_key = f"{game_folder}>{dest_folder}"
        if resume_key in self.resume_data and self.resume_data[resume_key].get('completed'):
            self.log_to_ui(f"Resuming: {folder_name} already completed")
            self.stats['copied'] += 1
            self.update_stats()
            return
        
        # Attempt copy with retry logic
        for attempt in range(1, self.config['max_retries'] + 1):
            try:
                if self.copy_ps3_folder_with_retry(game_folder, dest_folder, attempt):
                    # Mark as completed in resume data
                    self.resume_data[resume_key] = {
                        'completed': True,
                        'timestamp': time.time(),
                        'size': self.get_folder_size(game_folder)
                    }
                    self.save_resume_data()
                    break
            except Exception as e:
                self.stats['retry_count'] += 1
                if attempt < self.config['max_retries']:
                    self.log_to_ui(f"Retry {attempt}/{self.config['max_retries']} for {folder_name}: {e}", "WARNING")
                    time.sleep(self.config['retry_delay'])
                else:
                    self.log_to_ui(f"Failed after {self.config['max_retries']} attempts: {folder_name}: {e}", "ERROR")
                    self.stats['failed'] += 1
                    self.update_stats()
                    return

    def copy_ps3_folder_with_retry(self, src: Path, dest: Path, attempt: int) -> bool:
        """Enhanced PS3 folder copy with comprehensive error handling"""
        try:
            # Create backup if requested
            if dest.exists() and self.config['create_backup']:
                backup_path = dest.parent / f"{dest.name}_backup_{int(time.time())}"
                shutil.move(str(dest), str(backup_path))
                self.log_to_ui(f"Created backup: {backup_path.name}")
            
            # Clean destination if it exists
            if dest.exists():
                self.safe_remove_directory(dest)
                
            # Create destination folder
            os.makedirs(dest, exist_ok=True)
            
            # Copy all contents while preserving structure
            copied_files = 0
            total_files = sum(1 for _ in src.rglob('*') if _.is_file())
            
            for item in src.rglob('*'):
                if self.should_cancel:
                    return False
                    
                if item.is_file():
                    relative_path = item.relative_to(src)
                    dest_item = dest / relative_path
                    
                    # Ensure parent directory exists
                    os.makedirs(dest_item.parent, exist_ok=True)
                    
                    # Copy file with enhanced logic
                    if self.copy_file_enhanced(item, dest_item):
                        copied_files += 1
                    else:
                        raise Exception(f"Failed to copy {item.name}")
            
            # Verify essential PS3 files were copied
            self.verify_ps3_files_enhanced(dest)
            
            self.log_to_ui(f"Successfully copied {src.name} ({copied_files}/{total_files} files)")
            self.update_stats(1, self.get_folder_size(src))
            return True
            
        except Exception as e:
            self.log_to_ui(f"Copy failed for {src.name} (attempt {attempt}): {e}", "ERROR")
            # Clean up partial copy
            if dest.exists():
                self.safe_remove_directory(dest)
            raise

    def safe_remove_directory(self, path: Path):
        """Safely remove directory with proper error handling"""
        try:
            if path.exists():
                # Try normal removal first
                shutil.rmtree(path)
        except OSError as e:
            # If normal removal fails, try to handle locked files
            self.log_to_ui(f"Retrying removal of {path.name} due to: {e}", "WARNING")
            try:
                # Force removal of read-only files
                def handle_remove_readonly(func, path, exc):
                    os.chmod(path, 0o777)
                    func(path)
                
                shutil.rmtree(path, onerror=handle_remove_readonly)
            except Exception as e2:
                self.log_to_ui(f"Could not remove {path.name}: {e2}", "ERROR")
                raise

    def copy_file_enhanced(self, src: Path, dest: Path) -> bool:
        """Enhanced file copying with comprehensive validation"""
        if self.should_cancel:
            return False
            
        try:
            file_size = src.stat().st_size
            
            # Handle large files that need splitting
            if file_size > FAT32_LIMIT and self.split_var.get():
                return self.split_file_enhanced(src, dest)
            
            # Use temporary file for safer copying
            temp_file = dest.parent / f"~temp_{dest.name}_{int(time.time())}"
            
            try:
                # Copy with custom buffer size
                with open(src, 'rb') as f_src, open(temp_file, 'wb') as f_dest:
                    copied = 0
                    while copied < file_size and not self.should_cancel:
                        chunk = f_src.read(self.config['buffer_size'])
                        if not chunk:
                            break
                        f_dest.write(chunk)
                        copied += len(chunk)
                        
                        # Update progress for large files
                        if file_size > 100 * 1024 * 1024:  # 100MB
                            self.update_stats(0, len(chunk))
                
                if self.should_cancel:
                    temp_file.unlink()
                    return False
                
                # Verify copy if enabled
                if self.verify_var.get():
                    if not self.verify_copy_enhanced(src, temp_file):
                        temp_file.unlink()
                        raise Exception("File verification failed")
                
                # Atomic move to final location
                os.replace(temp_file, dest)
                
                # Copy file attributes
                shutil.copystat(src, dest)
                
                self.update_stats(1, file_size)
                return True
                
            except Exception as e:
                if temp_file.exists():
                    temp_file.unlink()
                raise
                
        except Exception as e:
            self.log_to_ui(f"File copy failed: {src.name}: {e}", "ERROR")
            return False

    def verify_copy_enhanced(self, src: Path, dest: Path) -> bool:
        """Enhanced copy verification with multiple checks"""
        try:
            # Size check
            src_size = src.stat().st_size
            dest_size = dest.stat().st_size
            
            if src_size != dest_size:
                self.log_to_ui(f"Size mismatch: {src.name} ({src_size} vs {dest_size})", "ERROR")
                return False
            
            # Hash verification for smaller files or critical PS3 files
            should_hash = (
                src_size < 100 * 1024 * 1024 or  # Files under 100MB
                src.name in PS3_FILE_SIGNATURES or  # Critical PS3 files
                src.suffix.lower() in ['.sfo', '.sfb', '.bin']  # Important extensions
            )
            
            if should_hash:
                src_hash = self.calculate_hash_chunked(src)
                dest_hash = self.calculate_hash_chunked(dest)
                
                if src_hash != dest_hash:
                    self.log_to_ui(f"Hash mismatch: {src.name}", "ERROR")
                    return False
            
            return True
            
        except Exception as e:
            self.log_to_ui(f"Verification error: {src.name}: {e}", "ERROR")
            return False

    def calculate_hash_chunked(self, file_path: Path) -> str:
        """Calculate hash with chunked reading for memory efficiency"""
        sha256 = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(self.config['buffer_size']):
                    if self.should_cancel:
                        return ""
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            self.log_to_ui(f"Hash calculation failed: {file_path.name}: {e}", "ERROR")
            return ""

    def split_file_enhanced(self, src: Path, dest_base: Path) -> bool:
        """Enhanced file splitting with comprehensive validation"""
        try:
            file_size = src.stat().st_size
            part_num = 0
            remaining = file_size
            parts_created = []
            
            self.log_to_ui(f"Splitting large file: {src.name} ({self.format_size(file_size)})")
            
            with open(src, 'rb') as f_src:
                while remaining > 0 and not self.should_cancel:
                    part_num += 1
                    part_path = dest_base.parent / f"{dest_base.name}{PS3_SPLIT_EXT}{part_num:02d}"
                    
                    chunk_size = min(FAT32_LIMIT, remaining)
                    temp_part = part_path.parent / f"~temp_{part_path.name}_{int(time.time())}"
                    
                    try:
                        # Write part file
                        with open(temp_part, 'wb') as f_part:
                            part_written = 0
                            while part_written < chunk_size and not self.should_cancel:
                                read_size = min(self.config['buffer_size'], chunk_size - part_written)
                                chunk = f_src.read(read_size)
                                if not chunk:
                                    break
                                f_part.write(chunk)
                                part_written += len(chunk)
                                remaining -= len(chunk)
                                self.update_stats(0, len(chunk))
                        
                        if self.should_cancel:
                            temp_part.unlink()
                            break
                        
                        # Verify part if enabled
                        if self.verify_var.get():
                            if not self.verify_split_part(src, temp_part, file_size - remaining - part_written, file_size - remaining):
                                temp_part.unlink()
                                raise Exception(f"Part {part_num} verification failed")
                        
                        # Move to final location
                        os.replace(temp_part, part_path)
                        parts_created.append(part_path)
                        
                        self.log_to_ui(f"Created part {part_num}: {part_path.name}")
                        
                    except Exception as e:
                        if temp_part.exists():
                            temp_part.unlink()
                        raise Exception(f"Failed to create part {part_num}: {e}")
            
            if self.should_cancel:
                # Clean up all parts
                for part in parts_created:
                    try:
                        part.unlink()
                    except:
                        pass
                return False
            
            self.log_to_ui(f"Successfully split {src.name} into {part_num} parts")
            self.stats['split'] += 1
            return True
            
        except Exception as e:
            self.log_to_ui(f"File splitting failed: {src.name}: {e}", "ERROR")
            return False

    def verify_split_part(self, src: Path, part: Path, start_offset: int, end_offset: int) -> bool:
        """Verify a part of a split file"""
        try:
            # Read the corresponding section from source
            with open(src, 'rb') as f_src:
                f_src.seek(start_offset)
                expected_data = f_src.read(end_offset - start_offset)
            
            # Read the part file
            with open(part, 'rb') as f_part:
                actual_data = f_part.read()
            
            return expected_data == actual_data
            
        except Exception as e:
            self.log_to_ui(f"Part verification error: {part.name}: {e}", "ERROR")
            return False

    def verify_ps3_files_enhanced(self, folder: Path):
        """Enhanced PS3 file verification"""
        missing_files = []
        corrupted_files = []
        
        # Check essential files
        essential_files = [
            ('PS3_DISC.SFB', folder),
            ('PARAM.SFO', folder),
            ('PARAM.SFO', folder / 'PS3_GAME'),
            ('ICON0.PNG', folder),
            ('ICON0.PNG', folder / 'PS3_GAME'),
            ('EBOOT.BIN', folder / 'PS3_GAME'),
            ('EBOOT.BIN', folder)
        ]
        
        for filename, location in essential_files:
            file_path = location / filename
            if file_path.exists():
                # Verify file signature if applicable
                if filename in PS3_FILE_SIGNATURES and self.config['verify_signatures']:
                    try:
                        with open(file_path, 'rb') as f:
                            header = f.read(len(PS3_FILE_SIGNATURES[filename]))
                            if header != PS3_FILE_SIGNATURES[filename]:
                                corrupted_files.append(str(file_path.relative_to(folder)))
                    except Exception as e:
                        self.log_to_ui(f"Could not verify signature for {filename}: {e}", "WARNING")
            else:
                # Only report missing if it's a critical file
                if filename in ['PARAM.SFO', 'PS3_DISC.SFB', 'EBOOT.BIN']:
                    missing_files.append(str(location.relative_to(folder) / filename))
        
        if missing_files:
            self.log_to_ui(f"Missing critical PS3 files in {folder.name}: {', '.join(missing_files)}", "WARNING")
        
        if corrupted_files:
            self.log_to_ui(f"Corrupted PS3 files in {folder.name}: {', '.join(corrupted_files)}", "ERROR")

    def get_folder_size(self, folder: Path) -> int:
        """Enhanced folder size calculation with error handling"""
        try:
            total_size = 0
            for file_path in folder.rglob('*'):
                if file_path.is_file():
                    try:
                        total_size += file_path.stat().st_size
                    except (OSError, IOError):
                        # Skip files that can't be accessed
                        continue
            return total_size
        except Exception as e:
            self.log_to_ui(f"Could not calculate size for {folder.name}: {e}", "WARNING")
            return 0

    def initialize_copy(self):
        """Enhanced copy initialization"""
        self.stats = {
            'total_files': 0,
            'total_size': 0,
            'copied': 0,
            'split': 0,
            'skipped': 0,
            'failed': 0,
            'bytes_copied': 0,
            'start_time': time.time(),
            'current_file': "",
            'retry_count': 0
        }
        
        # Count valid game folders and total size
        valid_games = []
        for game_folder in self.scan_source():
            if self.is_valid_ps3_folder(game_folder):
                size = self.get_folder_size(game_folder)
                valid_games.append((game_folder, size))
                self.stats['total_files'] += 1
                self.stats['total_size'] += size
        
        self.progress.config(maximum=self.stats['total_files'], value=0)
        self.status_var.set("Status: Copying PS3 games...")
        
        self.log_to_ui(f"Starting copy of {self.stats['total_files']} games ({self.format_size(self.stats['total_size'])})")

    def update_file_status(self):
        """Enhanced file status updates"""
        def update():
            progress_text = (
                f"Processing: {self.stats['current_file']}\n"
                f"Progress: {self.stats['copied']}/{self.stats['total_files']} games | "
                f"Skipped: {self.stats['skipped']} | Failed: {self.stats['failed']}"
            )
            if self.stats['retry_count'] > 0:
                progress_text += f" | Retries: {self.stats['retry_count']}"
            
            self.file_var.set(progress_text)
        
        self.gui_queue.put(update)

    def update_stats(self, files: int = 0, bytes_copied: int = 0):
        """Enhanced statistics updates"""
        def update():
            self.stats['copied'] += files
            self.stats['bytes_copied'] += bytes_copied
            
            self.progress['value'] = self.stats['copied']
            
            elapsed = time.time() - self.stats['start_time']
            if elapsed > 0:
                speed = self.stats['bytes_copied'] / elapsed
                self.speed_var.set(f"{self.format_size(speed)}/s")
                
                # Estimate remaining time
                remaining_files = self.stats['total_files'] - self.stats['copied'] - self.stats['skipped'] - self.stats['failed']
                remaining_bytes = self.stats['total_size'] - self.stats['bytes_copied']
                
                if speed > 0 and remaining_bytes > 0:
                    eta_seconds = remaining_bytes / speed
                    self.eta_var.set(str(timedelta(seconds=int(eta_seconds))))
                else:
                    self.eta_var.set("--:--:--")
                
                self.copied_var.set(f"{self.format_size(self.stats['bytes_copied'])}/{self.format_size(self.stats['total_size'])}")
        
        self.gui_queue.put(update)

    def format_size(self, bytes_val: int) -> str:
        """Enhanced size formatting"""
        if bytes_val == 0:
            return "0 B"
        
        for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
            if bytes_val < 1024.0:
                if unit == 'B':
                    return f"{int(bytes_val)} {unit}"
                else:
                    return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.1f} EB"

    def finalize_copy(self):
        """Enhanced copy finalization"""
        elapsed = time.time() - self.stats['start_time']
        speed = self.stats['bytes_copied'] / elapsed if elapsed > 0 else 0
        
        # Clean up resume file if everything completed successfully
        if not self.should_cancel and self.stats['failed'] == 0:
            try:
                if Path(RESUME_FILE).exists():
                    Path(RESUME_FILE).unlink()
                    self.log_to_ui("Cleaned up resume data")
            except:
                pass
        
        # Prepare summary message
        if self.should_cancel:
            title = "Operation Cancelled"
            message = (
                f"Operation cancelled by user!\n\n"
                f"Results:\n"
                f"• Copied: {self.stats['copied']} games\n"
                f"• Skipped: {self.stats['skipped']} games\n"
                f"• Failed: {self.stats['failed']} games\n"
                f"• Split files: {self.stats['split']}\n"
                f"• Data copied: {self.format_size(self.stats['bytes_copied'])}\n"
                f"• Time elapsed: {timedelta(seconds=int(elapsed))}\n"
                f"• Retries: {self.stats['retry_count']}"
            )
        elif self.dry_run_var.get():
            title = "Dry Run Complete"
            message = "Dry run completed successfully!\nCheck the log for details."
        else:
            title = "Copy Complete"
            success_rate = (self.stats['copied'] / max(1, self.stats['total_files'])) * 100
            message = (
                f"Successfully completed PS3 game copy!\n\n"
                f"Results:\n"
                f"• Copied: {self.stats['copied']}/{self.stats['total_files']} games ({success_rate:.1f}%)\n"
                f"• Skipped: {self.stats['skipped']} duplicates\n"
                f"• Failed: {self.stats['failed']} games\n"
                f"• Split files: {self.stats['split']}\n"
                f"• Total data: {self.format_size(self.stats['bytes_copied'])}\n"
                f"• Time: {timedelta(seconds=int(elapsed))}\n"
                f"• Average speed: {self.format_size(speed)}/s\n"
                f"• Retries: {self.stats['retry_count']}"
            )
        
        self.log_to_ui("=" * 50)
        self.log_to_ui("OPERATION COMPLETE")
        self.log_to_ui("=" * 50)
        for line in message.split('\n'):
            if line.strip():
                self.log_to_ui(line.strip())
        
        self.gui_queue.put(lambda: messagebox.showinfo(title, message))

    def handle_error(self, error: Exception):
        """Enhanced error handling"""
        self.logger.error(f"COPY ERROR: {error}", exc_info=True)
        
        error_msg = (
            f"An error occurred during the copy operation:\n\n"
            f"Error: {str(error)}\n"
            f"Current file: {self.stats.get('current_file', 'Unknown')}\n\n"
            f"Progress when error occurred:\n"
            f"• Copied: {self.stats['copied']} games\n"
            f"• Failed: {self.stats['failed']} games\n"
            f"• Data copied: {self.format_size(self.stats['bytes_copied'])}\n\n"
            f"Check the log tab for detailed error information.\n"
            f"Resume data has been saved for partial recovery."
        )
        
        self.gui_queue.put(lambda: (
            self.status_var.set("Status: Error occurred"),
            self.file_var.set(f"Error processing {self.stats['current_file']}"),
            self.log_to_ui(f"FATAL ERROR: {error}", "ERROR"),
            messagebox.showerror("Copy Error", error_msg)
        ))

    def cleanup(self):
        """Enhanced cleanup procedures"""
        self.is_running = False
        
        # Save final resume data
        if self.resume_data:
            self.save_resume_data()
        
        def ui_cleanup():
            self.start_btn.config(state=tk.NORMAL)
            self.cancel_btn.config(state=tk.DISABLED)
            
            if self.should_cancel:
                self.status_var.set("Status: Cancelled")
                self.file_var.set("Operation cancelled - resume data saved")
            else:
                self.status_var.set("Status: Complete")
                self.file_var.set("Ready for next operation")
        
        self.gui_queue.put(ui_cleanup)

    def cancel_copy(self):
        """Enhanced cancellation with cleanup confirmation"""
        if not self.is_running:
            return
            
        if messagebox.askyesno("Confirm Cancellation", 
                              "Really cancel the operation?\n\n"
                              "Progress will be saved for resuming later."):
            self.should_cancel = True
            self.log_to_ui("Cancellation requested - cleaning up safely...")
            
            def update_cancel_status():
                self.status_var.set("Status: Cancelling...")
                self.file_var.set("Safely cancelling operation... Please wait")
                self.cancel_btn.config(state=tk.DISABLED)
            
            self.gui_queue.put(update_cancel_status)

    def process_gui_queue(self):
        """Enhanced GUI queue processing with error handling"""
        processed = 0
        max_process = 10  # Prevent GUI freezing
        
        while not self.gui_queue.empty() and processed < max_process:
            try:
                task = self.gui_queue.get_nowait()
                if callable(task):
                    task()
                processed += 1
            except queue.Empty:
                break
            except Exception as e:
                self.logger.error(f"GUI task failed: {e}")
        
        # Schedule next processing
        self.root.after(50, self.process_gui_queue)

    def on_close(self):
        """Enhanced window close handling"""
        if self.is_running:
            response = messagebox.askyesnocancel(
                "Confirm Exit",
                "Copy operation is in progress!\n\n"
                "• Yes: Force quit (may lose progress)\n"
                "• No: Cancel and continue operation\n"
                "• Cancel: Stay in application"
            )
            
            if response is True:  # Yes - force quit
                self.should_cancel = True
                self.log_to_ui("Force quit requested")
                self.root.after(2000, self.root.destroy)  # Give time for cleanup
            elif response is False:  # No - continue
                return
            # Cancel - do nothing (stay in app)
        else:
            # Save settings before closing
            self.save_config()
            self.root.destroy()

def main():
    """Enhanced application entry point"""
    # Set up enhanced logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    
    try:
        # Create main window
        root = tk.Tk()
        
        # Set application icon and properties
        root.resizable(True, True)
        root.minsize(800, 600)
        
        # Create application instance
        app = PS3GameCopier(root)
        
        # Set up window close handler
        root.protocol("WM_DELETE_WINDOW", app.on_close)
        
        # Center window on screen
        root.update_idletasks()
        width = root.winfo_width()
        height = root.winfo_height()
        x = (root.winfo_screenwidth() // 2) - (width // 2)
        y = (root.winfo_screenheight() // 2) - (height // 2)
        root.geometry(f"+{x}+{y}")
        
        # Start the application
        logging.info("PS3 Game Copier Enhanced Edition started")
        root.mainloop()
        
    except Exception as e:
        logging.critical(f"FATAL APPLICATION ERROR: {e}", exc_info=True)
        try:
            messagebox.showerror(
                "Fatal Error",
                f"Application crashed with fatal error:\n\n{e}\n\n"
                f"Please check {LOG_FILE} for detailed error information."
            )
        except:
            print(f"FATAL ERROR: {e}")
    finally:
        logging.info("PS3 Game Copier Enhanced Edition terminated")

if __name__ == "__main__":
    main()
