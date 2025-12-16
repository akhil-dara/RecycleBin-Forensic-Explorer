import os
import sys
import time
import csv
import json
import hashlib
import logging
import datetime
import threading
import tempfile
import argparse
from pathlib import Path
import io
import re
import shutil
from zoneinfo import ZoneInfo

# PySide6 imports
from PySide6.QtCore import (Qt, QSize, QThread, Signal, Slot, QModelIndex,
                           QSortFilterProxyModel, QItemSelectionModel, QTimer, QRect, QFileInfo,
                           QMetaObject, Q_ARG, QSettings)
from PySide6.QtGui import (QIcon, QPixmap, QImage, QStandardItemModel, QStandardItem,
                          QFont, QColor, QPalette, QAction, QKeySequence, QCursor, QActionGroup)
from PySide6.QtWidgets import QGraphicsOpacityEffect
from PySide6.QtCore import QPropertyAnimation, QEasingCurve
from PySide6.QtWidgets import (QApplication, QMainWindow, QSplitter, QTreeView, QListView,
                              QVBoxLayout, QHBoxLayout, QWidget, QLabel, QPushButton,
                              QToolBar, QStatusBar, QFileDialog, QDialog, QTabWidget,
                              QLineEdit, QComboBox, QCheckBox, QRadioButton, QButtonGroup,
                              QProgressBar, QMessageBox, QMenu, QToolButton, QFrame,
                              QScrollArea, QGridLayout, QSizePolicy, QStyle, QStyleFactory,
                              QTextEdit, QSpacerItem, QGroupBox, QFormLayout, QHeaderView,
                              QTableWidget, QTableWidgetItem, QProgressDialog)
from PySide6.QtWidgets import QStyledItemDelegate
from PySide6.QtWidgets import QFileIconProvider

# Third-party libraries for forensics
import pyewf
import pytsk3

# Configure logging
logger = logging.getLogger('RecycleBinForensics')

def setup_logging(log_file=None, file_level=logging.INFO, console_level=logging.INFO):
    """Set up logging configuration with persistent log files."""
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Console handler
    console = logging.StreamHandler()
    console.setLevel(console_level)
    console.setFormatter(formatter)
    logger.addHandler(console)
    
    # Always create a persistent log file with timestamp
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    os.makedirs(log_dir, exist_ok=True)
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    persistent_log_file = os.path.join(log_dir, f"recycle_bin_forensics_{timestamp}.log")
    
    file_handler = logging.FileHandler(persistent_log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Log application start
    logger.info("="*60)
    logger.info(f"Application started at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Log file: {persistent_log_file}")
    logger.info("="*60)
    
    # Additional file handler (if specified by user)
    if log_file:
        user_file_handler = logging.FileHandler(log_file, encoding='utf-8')
        user_file_handler.setLevel(file_level)
        user_file_handler.setFormatter(formatter)
        logger.addHandler(user_file_handler)

class EWFImgInfo(pytsk3.Img_Info):
    """Wrapper for EWF (Expert Witness Format) image files."""
    
    def __init__(self, ewf_handle):
        self.ewf_handle = ewf_handle
        super(EWFImgInfo, self).__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)
    
    def close(self):
        self.ewf_handle.close()
    
    def read(self, offset, size):
        self.ewf_handle.seek(offset)
        return self.ewf_handle.read(size)
    
    def get_size(self):
        return self.ewf_handle.get_media_size()

def parse_dollar_i_file(file_data, file_name):
    """Parse a $I file to extract metadata."""
    try:
        result = {}
        
        # Check if file is large enough to contain version
        if len(file_data) < 8:
            logger.warning(f"$I file too small: {file_name}")
            return None
        
        # Extract version (first 8 bytes)
        result['version'] = int.from_bytes(file_data[0:8], byteorder='little')
        
        # Extract original file size (next 8 bytes)
        if len(file_data) >= 16:
            result['original_size'] = int.from_bytes(file_data[8:16], byteorder='little')
        else:
            result['original_size'] = 0
        
        # Extract deletion time (next 8 bytes)
        if len(file_data) >= 24:
            filetime = int.from_bytes(file_data[16:24], byteorder='little')
            # Convert Windows FILETIME to Unix timestamp and then to datetime
            unix_time = (filetime - 116444736000000000) / 10000000
            result['deletion_time'] = datetime.datetime.fromtimestamp(unix_time, tz=datetime.timezone.utc)
        else:
            result['deletion_time'] = None
        
        # Extract original path based on version
        if result['version'] == 1:  # Windows Vista/7/8/8.1
            # For version 1, path starts at offset 24
            path_bytes = file_data[24:]
            # Find null terminator (double-null for UTF-16LE)
            null_pos = 0
            for i in range(0, len(path_bytes) - 1, 2):
                if path_bytes[i] == 0 and path_bytes[i+1] == 0:
                    null_pos = i
                    break
            
            if null_pos > 0:
                path = path_bytes[:null_pos].decode('utf-16le', errors='replace')
            else:
                path = path_bytes.decode('utf-16le', errors='replace').rstrip('\x00')
            
            result['original_path'] = path
            
        elif result['version'] == 2:  # Windows 10/11
            # For version 2, scan from offset 28 until first double-null
            start = 28
            end = start
            while end+1 < len(file_data):
                if file_data[end] == 0 and file_data[end+1] == 0:
                    break
                end += 2
            
            path_bytes = file_data[start:end]
            path = path_bytes.decode('utf-16le', errors='replace')
            result['original_path'] = path
            
        else:
            logger.warning(f"Unknown $I file version: {result['version']} for {file_name}")
            # Try fallback method - scan for Windows path pattern
            found_path = False
            for i in range(24, len(file_data) - 6, 2):
                if (i + 6 < len(file_data) and
                    file_data[i] in range(65, 91) and  # A-Z
                    file_data[i+1] == 0 and
                    file_data[i+2] == 58 and  # :
                    file_data[i+3] == 0 and
                    file_data[i+4] == 92 and  # \
                    file_data[i+5] == 0):
                    
                    # Extract path starting from this position
                    start = i
                    end = start
                    while end+1 < len(file_data):
                        if file_data[end] == 0 and file_data[end+1] == 0:
                            break
                        end += 2
                    
                    path_bytes = file_data[start:end]
                    path = path_bytes.decode('utf-16le', errors='replace')
                    if len(path) > 3:  # More than just "C:\"
                        result['original_path'] = path
                        found_path = True
                        break
            
            if not found_path:
                result['original_path'] = f"Unknown version: {result['version']}"
        
        return result
        
    except Exception as e:
        logger.error(f"Error parsing $I file {file_name}: {str(e)}")
        return None

def preserve_timestamps(file_path, created_time=None, modified_time=None, accessed_time=None):
    """Preserve file timestamps using platform-specific methods."""
    try:
        # Check if path exists
        if not os.path.exists(file_path):
            return
        
        # Skip directories - they don't need timestamp preservation
        if os.path.isdir(file_path):
            return
        
        if os.name == 'nt':  # Windows
            try:
                import win32file
                import win32con
                import pywintypes
                
                # Use FILE_FLAG_BACKUP_SEMANTICS for directories if needed
                flags = win32con.FILE_ATTRIBUTE_NORMAL
                
                handle = win32file.CreateFile(
                    file_path,
                    win32con.GENERIC_WRITE,
                    win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                    None, 
                    win32con.OPEN_EXISTING,
                    flags, 
                    None
                )
                
                win_created = None
                win_accessed = None
                win_modified = None
                
                if created_time:
                    win_created = pywintypes.Time(int(created_time.timestamp()))
                if accessed_time:
                    win_accessed = pywintypes.Time(int(accessed_time.timestamp()))
                if modified_time:
                    win_modified = pywintypes.Time(int(modified_time.timestamp()))
                
                win32file.SetFileTime(handle, win_created, win_accessed, win_modified)
                handle.close()
                
            except ImportError:
                # Fallback to os.utime for modification time only
                if modified_time:
                    timestamp = modified_time.timestamp()
                    os.utime(file_path, (timestamp, timestamp))
            except Exception:
                # Silently fail for timestamp preservation - not critical
                pass
        else:
            # Unix/Linux - use os.utime
            if modified_time and accessed_time:
                os.utime(file_path, (accessed_time.timestamp(), modified_time.timestamp()))
            elif modified_time:
                timestamp = modified_time.timestamp()
                os.utime(file_path, (timestamp, timestamp))
                
    except Exception as e:
        # Log at debug level since timestamp preservation is not critical
        logger.debug(f"Could not preserve timestamps for {file_path}: {str(e)}")

class RecycleBinParser:
    """Parser for Windows Recycle Bin artifacts from E01 images."""
    
    def __init__(self, image_path, output_dir=None, csv_filename="recycle_bin_artifacts.csv",
                 partition_index=None, quiet=False, debug=False):
        self.image_path = image_path
        self.output_dir = output_dir
        self.csv_filename = csv_filename
        self.partition_index = partition_index
        self.quiet = quiet
        self.debug = debug
        
        # Statistics
        self.stats = {
            'partitions_found': 0,
            'i_files_found': 0,
            'i_files_parsed': 0,
            'r_files_found': 0,
            'sid_dirs_found': 0,
            'start_time': time.time(),
            'end_time': None,
            'duration': None
        }
        
        # Initialize components
        self.img_info = None
        self.fs_info = None
        self.partitions = []
        self.artifacts = []
        
        # Hash cache for performance (key: file_addr, value: {hash_type: hash_value})
        self._hash_cache = {}
    
    def open_image(self):
        """Open the E01 image file."""
        logger.info(f"Opening image: {self.image_path}")
        
        if not os.path.exists(self.image_path):
            raise FileNotFoundError(f"Image file not found: {self.image_path}")
        
        if self.image_path.lower().endswith('.e01'):
            try:
                # Normalize path to use OS-specific separators
                normalized_path = os.path.normpath(self.image_path)
                
                # Use the normalized path for globbing
                filenames = pyewf.glob(normalized_path)
                if not filenames:
                    raise RuntimeError(f"No E01 segments found for {normalized_path}")
                
                ewf_handle = pyewf.handle()
                ewf_handle.open(filenames)
                self.img_info = EWFImgInfo(ewf_handle)
                
                logger.info(f"Successfully opened E01 image: {self.image_path}")
                
            except Exception as e:
                raise RuntimeError(f"Error opening E01 image: {str(e)}")
        else:
            try:
                self.img_info = pytsk3.Img_Info(self.image_path)
                logger.info(f"Successfully opened raw image: {self.image_path}")
            except Exception as e:
                raise RuntimeError(f"Error opening image: {str(e)}")
    
    def detect_partitions(self):
        """Detect partitions in the image."""
        logger.info("Detecting partitions...")
        
        try:
            volume = pytsk3.Volume_Info(self.img_info)
            
            for part in volume:
                try:
                    desc = part.desc.decode('utf-8', errors='replace')
                    if desc.lower() not in ['unallocated', 'extended', 'primary table']:
                        # Calculate size in GB
                        size_bytes = part.len * volume.info.block_size
                        size_gb = size_bytes / (1024**3)
                        
                        self.partitions.append({
                            'addr': part.addr,
                            'desc': desc,
                            'offset': part.start * volume.info.block_size,
                            'size': size_bytes,
                            'size_gb': size_gb
                        })
                        
                        logger.info(f"Found partition: {desc} ({size_gb:.2f} GB)")
                        
                except Exception as e:
                    logger.debug(f"Error processing partition: {str(e)}")
            
            self.stats['partitions_found'] = len(self.partitions)
            logger.info(f"Detected {len(self.partitions)} partitions")
            
        except Exception as e:
            logger.warning(f"Error detecting partitions: {str(e)}")
            try:
                self.fs_info = pytsk3.FS_Info(self.img_info)
                
                # Get volume size
                size_bytes = self.img_info.get_size()
                size_gb = size_bytes / (1024**3)
                
                self.partitions.append({
                    'addr': 0,
                    'desc': 'Logical Volume',
                    'offset': 0,
                    'size': size_bytes,
                    'size_gb': size_gb
                })
                
                self.stats['partitions_found'] = 1
                logger.info(f"Detected logical volume (no partition table) - {size_gb:.2f} GB")
                
            except Exception as inner_e:
                raise RuntimeError(f"Failed to open as logical volume: {str(inner_e)}")
    
    def select_partition(self, partition_index):
        """Select a partition to analyze."""
        if not self.partitions:
            raise RuntimeError("No partitions detected")
        
        if not (0 <= partition_index < len(self.partitions)):
            raise ValueError(f"Invalid partition index: {partition_index}")
        
        selected_part = self.partitions[partition_index]
        logger.info(f"Selected partition: {selected_part['desc']} ({selected_part['size_gb']:.2f} GB)")
        
        try:
            self.fs_info = pytsk3.FS_Info(self.img_info, offset=selected_part['offset'])
            logger.info("Filesystem opened successfully")
        except Exception as e:
            raise RuntimeError(f"Error opening filesystem: {str(e)}")
    
    def find_recycle_bin(self):
        """Find the Recycle Bin directory and return its path."""
        logger.info("Searching for Recycle Bin...")
        
        recycle_bin_paths = ["/$Recycle.Bin", "/Recycle.Bin", "/RECYCLER", "/RECYCLED"]
        
        # Try standard paths first
        for path in recycle_bin_paths:
            try:
                self.fs_info.open_dir(path=path)
                logger.info(f"Found Recycle Bin at: {path}")
                return path
            except Exception:
                continue
        
        # If not found, scan root directory
        try:
            root_dir = self.fs_info.open_dir(path="/")
            for entry in root_dir:
                try:
                    name = entry.info.name.name.decode('utf-8', errors='replace')
                    if name.lower() in ["$recycle.bin", "recycle.bin", "recycler", "recycled"]:
                        path = f"/{name}"
                        logger.info(f"Found Recycle Bin at: {path}")
                        return path
                except:
                    continue
        except Exception as e:
            logger.warning(f"Error scanning root directory: {str(e)}")
        
        logger.warning("Recycle Bin not found")
        return None
    
    def collect_sid_directories(self, recycle_bin_path):
        """Collect all SID directories in the Recycle Bin."""
        logger.info("Collecting SID directories...")
        
        sid_dirs = []
        
        try:
            recycle_bin_dir = self.fs_info.open_dir(path=recycle_bin_path)
            
            for entry in recycle_bin_dir:
                try:
                    name = entry.info.name.name.decode('utf-8', errors='replace')
                    if name not in ['.', '..'] and entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                        sid_dirs.append({
                            'name': name,
                            'path': f"{recycle_bin_path}/{name}",
                            'addr': entry.info.meta.addr
                        })
                        logger.info(f"Found SID directory: {name}")
                        
                except Exception as e:
                    logger.debug(f"Error processing directory entry: {str(e)}")
            
            self.stats['sid_dirs_found'] = len(sid_dirs)
            logger.info(f"Found {len(sid_dirs)} SID directories")
            
        except Exception as e:
            logger.error(f"Error collecting SID directories: {str(e)}")
        
        return sid_dirs

    def _resolve_entry_meta(self, entry, entry_name):
        """Ensure NTFS metadata is available even for deleted entries."""
        meta = entry.info.meta
        meta_addr = None

        if meta:
            meta_addr = meta.addr
        else:
            meta_addr = getattr(entry.info, 'meta_addr', None)
            if meta_addr not in [None, 0]:
                file_obj = None
                try:
                    file_obj = self.fs_info.open_meta(meta_addr)
                    meta = file_obj.info.meta
                except Exception as e:
                    logger.debug(f"Failed to load metadata for {entry_name} (addr={meta_addr}): {str(e)}")
                    meta = None
                finally:
                    if file_obj and hasattr(file_obj, 'close'):
                        try:
                            file_obj.close()
                        except Exception:
                            pass
        return meta, meta_addr
    
    def collect_i_files(self, sid_dirs):
        """Collect all $I files from SID directories."""
        logger.info("Collecting $I files...")
        
        i_files = []
        
        for sid_dir in sid_dirs:
            sid_name = sid_dir['name']
            sid_path = sid_dir['path']
            
            logger.info(f"Processing SID directory: {sid_name}")
            
            try:
                dir_obj = self.fs_info.open_dir(path=sid_path)
                
                # First pass: collect all $I and $R files
                i_file_map = {}
                r_file_map = {}
                
                for entry in dir_obj:
                    try:
                        name = entry.info.name.name.decode('utf-8', errors='replace')
                        if name in ['.', '..']:
                            continue

                        upper_name = name.upper()
                        if not (upper_name.startswith('$I') or upper_name.startswith('$R')):
                            continue

                        meta, meta_addr = self._resolve_entry_meta(entry, name)
                        if not meta_addr:
                            logger.debug(f"Skipping entry {name} in {sid_name}: missing metadata address")
                            continue

                        is_directory = bool(meta and meta.type == pytsk3.TSK_FS_META_TYPE_DIR)
                        size = meta.size if meta else 0
                        created = meta.crtime if meta else None
                        modified = meta.mtime if meta else None
                        accessed = meta.atime if meta else None
                        path = f"{sid_path}/{name}"

                        if upper_name.startswith('$I'):
                            i_file_map[upper_name] = {
                                'name': name,
                                'path': path,
                                'addr': meta_addr,
                                'size': size,
                                'sid': sid_name,
                                'created': created,
                                'modified': modified,
                                'accessed': accessed
                            }
                            self.stats['i_files_found'] += 1
                            
                        elif upper_name.startswith('$R'):
                            r_file_map[upper_name] = {
                                'name': name,
                                'path': path,
                                'addr': meta_addr,
                                'size': size,
                                'created': created,
                                'modified': modified,
                                'accessed': accessed,
                                'is_directory': is_directory
                            }
                            self.stats['r_files_found'] += 1
                                
                    except Exception as e:
                        logger.debug(f"Error processing file entry: {str(e)}")
                
                # Second pass: match $I files with $R files
                for i_upper_name, i_file in i_file_map.items():
                    r_key = '$R' + i_upper_name[2:]
                    r_entry = r_file_map.get(r_key)
                    i_file['r_file_name'] = r_entry['name'] if r_entry else '$R' + i_file['name'][2:]
                    
                    if r_entry:
                        i_file['r_file_exists'] = True
                        i_file['r_file_size'] = r_entry['size']
                        i_file['r_file_addr'] = r_entry['addr']
                        i_file['r_file_created'] = r_entry['created']
                        i_file['r_file_modified'] = r_entry['modified']
                        i_file['r_file_accessed'] = r_entry['accessed']
                        i_file['r_file_is_directory'] = r_entry['is_directory']
                    else:
                        i_file['r_file_exists'] = False
                        i_file['r_file_size'] = 0
                        i_file['r_file_addr'] = None
                        i_file['r_file_created'] = None
                        i_file['r_file_modified'] = None
                        i_file['r_file_accessed'] = None
                        i_file['r_file_is_directory'] = False
                    
                    i_files.append(i_file)
                
                logger.info(f"Found {len(i_file_map)} $I files and {len(r_file_map)} $R files in {sid_name}")
                
            except Exception as e:
                logger.error(f"Error processing SID directory {sid_name}: {str(e)}")
        
        return i_files
    
    def process_i_files(self, i_files):
        """Process all collected $I files."""
        logger.info(f"Processing {len(i_files)} $I files...")
        
        for i_file in i_files:
            try:
                file_obj = self.fs_info.open_meta(i_file['addr'])
                file_size = i_file['size']
                
                if file_size == 0:
                    logger.warning(f"Empty $I file: {i_file['name']}")
                    continue
                
                # Read file content
                file_content = b''
                offset = 0
                while offset < file_size:
                    available = min(1024*1024, file_size - offset)  # Read in 1MB chunks
                    data = file_obj.read_random(offset, available)
                    if not data:
                        break
                    file_content += data
                    offset += len(data)
                
                if not file_content:
                    logger.warning(f"Failed to read $I file: {i_file['name']}")
                    continue
                
                # Parse the $I file
                parsed_data = parse_dollar_i_file(file_content, i_file['name'])
                
                if parsed_data:
                    # Add file information
                    parsed_data['sid'] = i_file['sid']
                    parsed_data['i_file_name'] = i_file['name']
                    parsed_data['r_file_name'] = i_file['r_file_name']
                    parsed_data['r_file_recovered'] = i_file['r_file_exists']
                    parsed_data['r_file_size'] = i_file['r_file_size']
                    parsed_data['r_file_addr'] = i_file['r_file_addr']
                    parsed_data['r_file_is_directory'] = i_file.get('r_file_is_directory', False)
                    
                    # Add timestamps from $I file (timestamps from forensic artifacts are UTC)
                    if i_file['created']:
                        parsed_data['created_time'] = datetime.datetime.fromtimestamp(i_file['created'], tz=datetime.timezone.utc)
                    if i_file['modified']:
                        parsed_data['modified_time'] = datetime.datetime.fromtimestamp(i_file['modified'], tz=datetime.timezone.utc)
                    if i_file['accessed']:
                        parsed_data['accessed_time'] = datetime.datetime.fromtimestamp(i_file['accessed'], tz=datetime.timezone.utc)
                    
                    # Add timestamps from $R file if available
                    if i_file['r_file_exists'] and i_file['r_file_created']:
                        parsed_data['r_file_created_time'] = datetime.datetime.fromtimestamp(i_file['r_file_created'], tz=datetime.timezone.utc)
                        parsed_data['r_file_modified_time'] = datetime.datetime.fromtimestamp(i_file['r_file_modified'], tz=datetime.timezone.utc)
                        parsed_data['r_file_accessed_time'] = datetime.datetime.fromtimestamp(i_file['r_file_accessed'], tz=datetime.timezone.utc)
                    
                    # Extract file extension from original path
                    file_ext = os.path.splitext(parsed_data['original_path'])[1].lower()
                    parsed_data['file_ext'] = file_ext
                    
                    # Get file type category
                    if parsed_data['r_file_is_directory']:
                        parsed_data['file_type'] = "Folder"
                    else:
                        parsed_data['file_type'] = self.categorize_file_type(file_ext)
                    
                    # Initialize folder content fields
                    parsed_data['is_child_item'] = False
                    parsed_data['parent_folder_path'] = None
                    parsed_data['relative_path_in_folder'] = None
                    parsed_data['folder_level'] = 0
                    
                    self.artifacts.append(parsed_data)
                    self.stats['i_files_parsed'] += 1
                    
            except Exception as e:
                logger.error(f"Error processing $I file {i_file['name']}: {str(e)}")
        
        # Update statistics
        self.stats['end_time'] = time.time()
        self.stats['duration'] = self.stats['end_time'] - self.stats['start_time']
        
        logger.info(f"Processed {self.stats['i_files_parsed']} $I files in {self.stats['duration']:.2f} seconds")
    
    def scan_folder_contents(self, artifact, root_path=None):
        """Recursively scan contents of a deleted folder."""
        if not artifact.get('r_file_is_directory') or not artifact.get('r_file_addr'):
            return []
        
        # Track the root folder path for relative path calculation
        if root_path is None:
            root_path = artifact['original_path']
        
        folder_contents = []
        
        try:
            # Open the directory
            dir_obj = self.fs_info.open_meta(artifact['r_file_addr'])
            
            # Scan directory entries
            for entry in dir_obj.as_directory():
                try:
                    name = entry.info.name.name.decode('utf-8', errors='replace')
                    
                    # Skip . and .. entries
                    if name in ['.', '..']:
                        continue
                    
                    if entry.info.meta:
                        is_directory = entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR
                        
                        # Create child artifact
                        child_artifact = {
                            'sid': artifact['sid'],
                            'i_file_name': f"{artifact['i_file_name']}_child_{name}",
                            'r_file_name': f"{artifact['r_file_name']}_child_{name}",
                            'version': artifact['version'],
                            'original_size': entry.info.meta.size,
                            'deletion_time': artifact['deletion_time'],
                            'original_path': os.path.join(artifact['original_path'], name),
                            'r_file_recovered': True,
                            'r_file_size': entry.info.meta.size,
                            'r_file_addr': entry.info.meta.addr,
                            'r_file_is_directory': is_directory,
                            'file_ext': os.path.splitext(name)[1].lower() if not is_directory else '',
                            'file_type': "Folder" if is_directory else self.categorize_file_type(os.path.splitext(name)[1].lower()),
                            
                            # Child-specific fields
                            'is_child_item': True,
                            'parent_folder_path': root_path,
                            'relative_path_in_folder': os.path.relpath(os.path.join(artifact['original_path'], name), root_path) if is_directory else (os.path.relpath(artifact['original_path'], root_path) if artifact['original_path'] != root_path else ''),
                            'folder_level': artifact.get('folder_level', 0) + 1,
                            
                            # Timestamps (forensic timestamps are UTC)
                            'created_time': datetime.datetime.fromtimestamp(entry.info.meta.crtime, tz=datetime.timezone.utc) if entry.info.meta.crtime else None,
                            'modified_time': datetime.datetime.fromtimestamp(entry.info.meta.mtime, tz=datetime.timezone.utc) if entry.info.meta.mtime else None,
                            'accessed_time': datetime.datetime.fromtimestamp(entry.info.meta.atime, tz=datetime.timezone.utc) if entry.info.meta.atime else None,
                            'r_file_created_time': datetime.datetime.fromtimestamp(entry.info.meta.crtime, tz=datetime.timezone.utc) if entry.info.meta.crtime else None,
                            'r_file_modified_time': datetime.datetime.fromtimestamp(entry.info.meta.mtime, tz=datetime.timezone.utc) if entry.info.meta.mtime else None,
                            'r_file_accessed_time': datetime.datetime.fromtimestamp(entry.info.meta.atime, tz=datetime.timezone.utc) if entry.info.meta.atime else None,
                        }
                        
                        folder_contents.append(child_artifact)
                        
                        # Recursively scan subdirectories
                        if is_directory:
                            subdir_contents = self.scan_folder_contents(child_artifact, root_path)
                            folder_contents.extend(subdir_contents)
                            
                except Exception as e:
                    logger.debug(f"Error processing directory entry {name}: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error scanning folder contents: {str(e)}")
        
        return folder_contents
    
    def categorize_file_type(self, extension):
        """Categorize file based on extension."""
        image_exts = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp']
        document_exts = ['.doc', '.docx', '.pdf', '.txt', '.rtf', '.odt', '.xls', '.xlsx', '.ppt', '.pptx']
        video_exts = ['.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv', '.webm']
        audio_exts = ['.mp3', '.wav', '.ogg', '.flac', '.aac', '.wma']
        archive_exts = ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2']
        executable_exts = ['.exe', '.dll', '.bat', '.cmd', '.msi', '.sys']
        
        if extension in image_exts:
            return "Image"
        elif extension in document_exts:
            return "Document"
        elif extension in video_exts:
            return "Video"
        elif extension in audio_exts:
            return "Audio"
        elif extension in archive_exts:
            return "Archive"
        elif extension in executable_exts:
            return "Executable"
        else:
            return "Other"
    
    def save_to_csv(self, csv_path, selected_artifacts=None, hash_types=None, include_recursive=False, timezone="UTC", precomputed_folder_contents=False):
        """Save artifacts to a CSV file."""
        artifacts_to_save = selected_artifacts if selected_artifacts else self.artifacts
        
        if not artifacts_to_save:
            logger.warning("No artifacts to save")
            return False
        
        def format_datetime_for_csv(dt, tz_name):
            """Format datetime with timezone conversion for CSV export in ISO 8601 format."""
            if dt is None:
                return ""
            try:
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=ZoneInfo("UTC"))
                target_tz = ZoneInfo(tz_name)
                dt_converted = dt.astimezone(target_tz)
                # ISO 8601 format with T separator and timezone offset
                return dt_converted.strftime('%Y-%m-%dT%H:%M:%S%z')
            except Exception:
                if isinstance(dt, datetime.datetime):
                    return dt.strftime('%Y-%m-%dT%H:%M:%S')
                return str(dt) if dt else ""
        
        def format_size(size_bytes):
            """Format file size in human-readable form."""
            if size_bytes is None:
                return ""
            if size_bytes < 1024:
                return f"{size_bytes} B"
            elif size_bytes < 1024 * 1024:
                return f"{size_bytes/1024:.1f} KB"
            elif size_bytes < 1024 * 1024 * 1024:
                return f"{size_bytes/(1024*1024):.1f} MB"
            else:
                return f"{size_bytes/(1024*1024*1024):.1f} GB"
        
        try:
            with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                # Define all possible fieldnames with timezone indicator
                tz_suffix = f" ({timezone})"
                fieldnames = ['sid', 'i_file_name', 'r_file_name', 'version', 
                             'original_size', 'original_size_formatted',
                             f'deletion_time{tz_suffix}', 'original_path', 
                             'r_file_size', 'r_file_size_formatted', 'r_file_recovered',
                             'file_ext', 'file_type', 'r_file_is_directory',
                             f'created_time{tz_suffix}', f'modified_time{tz_suffix}', f'accessed_time{tz_suffix}', 
                             f'r_file_created_time{tz_suffix}', f'r_file_modified_time{tz_suffix}', f'r_file_accessed_time{tz_suffix}']
                
                # Map original field names to new names with timezone
                date_field_map = {
                    'deletion_time': f'deletion_time{tz_suffix}',
                    'created_time': f'created_time{tz_suffix}',
                    'modified_time': f'modified_time{tz_suffix}',
                    'accessed_time': f'accessed_time{tz_suffix}',
                    'r_file_created_time': f'r_file_created_time{tz_suffix}',
                    'r_file_modified_time': f'r_file_modified_time{tz_suffix}',
                    'r_file_accessed_time': f'r_file_accessed_time{tz_suffix}',
                }
                
                # Add recursive fields if enabled
                if include_recursive:
                    fieldnames.extend(['is_child_item', 'parent_folder_path', 'relative_path_in_folder', 'folder_level'])
                
                # Add hash fields if requested
                if hash_types:
                    for hash_type in hash_types:
                        fieldnames.append(f"{hash_type}_hash")
                
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                
                for artifact in artifacts_to_save:
                    # Convert datetime objects to strings with timezone
                    row_data = artifact.copy()
                    for orig_field, new_field in date_field_map.items():
                        if row_data.get(orig_field):
                            row_data[new_field] = format_datetime_for_csv(row_data[orig_field], timezone)
                            if orig_field in row_data:
                                del row_data[orig_field]
                        else:
                            row_data[new_field] = ""
                    
                    # Add formatted size columns
                    row_data['original_size_formatted'] = format_size(row_data.get('original_size'))
                    row_data['r_file_size_formatted'] = format_size(row_data.get('r_file_size'))
                    
                    writer.writerow(row_data)
                    
                    # Include folder contents if recursive option is enabled
                    if include_recursive and artifact.get('r_file_is_directory'):
                        # Use precomputed folder contents if available (already has hashes)
                        if precomputed_folder_contents and '_folder_contents' in artifact:
                            folder_contents = artifact['_folder_contents']
                        else:
                            folder_contents = self.scan_folder_contents(artifact)
                        for child_artifact in folder_contents:
                            child_row = child_artifact.copy()
                            for orig_field, new_field in date_field_map.items():
                                if child_row.get(orig_field):
                                    child_row[new_field] = format_datetime_for_csv(child_row[orig_field], timezone)
                                    if orig_field in child_row:
                                        del child_row[orig_field]
                                else:
                                    child_row[new_field] = ""
                            # Add formatted size columns for child items
                            child_row['original_size_formatted'] = format_size(child_row.get('original_size'))
                            child_row['r_file_size_formatted'] = format_size(child_row.get('r_file_size'))
                            writer.writerow(child_row)
                
                logger.info(f"Saved {len(artifacts_to_save)} artifacts to {csv_path}")
                return True
                
        except Exception as e:
            logger.error(f"Error saving to CSV: {str(e)}")
            return False
    
    def calculate_file_hash(self, file_addr, hash_types):
        """Calculate hash for a file with caching for performance."""
        if not file_addr:
            return {}
        
        # Check cache first
        cache_key = file_addr
        if cache_key in self._hash_cache:
            cached = self._hash_cache[cache_key]
            # Return only requested hash types from cache
            result = {}
            all_cached = True
            for ht in hash_types:
                key = f"{ht}_hash"
                if key in cached:
                    result[key] = cached[key]
                else:
                    all_cached = False
                    break
            if all_cached:
                return result
        
        hash_results = {}
        
        try:
            file_obj = self.fs_info.open_meta(file_addr)
            file_size = file_obj.info.meta.size
            
            # Initialize hash objects
            hash_objects = {}
            for hash_type in hash_types:
                if hash_type == 'md5':
                    hash_objects[hash_type] = hashlib.md5()
                elif hash_type == 'sha1':
                    hash_objects[hash_type] = hashlib.sha1()
                elif hash_type == 'sha256':
                    hash_objects[hash_type] = hashlib.sha256()
            
            # Read file in chunks and update hash objects
            offset = 0
            chunk_size = 1024 * 1024  # 1MB chunks
            
            try:
                while offset < file_size:
                    try:
                        data = file_obj.read_random(offset, min(chunk_size, file_size - offset))
                        if not data:
                            break
                        
                        # Update all hash objects
                        for hash_obj in hash_objects.values():
                            hash_obj.update(data)
                        
                        offset += len(data)
                        
                    except Exception as read_error:
                        logger.warning(f"Error reading file at offset {offset}: {str(read_error)}")
                        # Try to continue with next chunk
                        offset += chunk_size
                        if offset > file_size:
                            break
                            
            except Exception as e:
                logger.error(f"Error during hash calculation: {str(e)}")
            
            # Get hexadecimal digests
            for hash_type, hash_obj in hash_objects.items():
                hash_results[f"{hash_type}_hash"] = hash_obj.hexdigest()
            
            # Cache the results
            if hash_results:
                if cache_key not in self._hash_cache:
                    self._hash_cache[cache_key] = {}
                self._hash_cache[cache_key].update(hash_results)
            
            return hash_results
            
        except Exception as e:
            logger.error(f"Error calculating hash: {str(e)}")
            return {}
    
    def export_file(self, artifact, output_path):
        """Export a recovered file to disk."""
        if not artifact.get('r_file_recovered') or not artifact.get('r_file_addr'):
            logger.warning(f"File not recoverable: {artifact.get('original_path')}")
            return False
        
        try:
            file_obj = self.fs_info.open_meta(artifact['r_file_addr'])
            file_size = artifact['r_file_size']
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            # Handle directories
            if artifact.get('r_file_is_directory', False):
                # Create directory
                os.makedirs(output_path, exist_ok=True)
                logger.info(f"Created directory: {output_path}")
                
                # Export folder contents recursively
                folder_contents = self.scan_folder_contents(artifact)
                for child_artifact in folder_contents:
                    # Build proper path based on item type:
                    # - For directories: relative_path_in_folder already includes dir name
                    # - For files: relative_path_in_folder is parent dir, need to add filename
                    child_filename = os.path.basename(child_artifact.get('original_path', ''))
                    relative_dir = child_artifact.get('relative_path_in_folder', '')
                    is_child_dir = child_artifact.get('r_file_is_directory', False)
                    
                    if is_child_dir:
                        # For directories, relative_path_in_folder is the full relative path
                        if relative_dir:
                            child_output_path = os.path.join(output_path, relative_dir)
                        else:
                            child_output_path = os.path.join(output_path, child_filename)
                    else:
                        # For files, relative_path_in_folder is parent dir path
                        if relative_dir:
                            child_output_path = os.path.join(output_path, relative_dir, child_filename)
                        else:
                            child_output_path = os.path.join(output_path, child_filename)
                    self.export_file(child_artifact, child_output_path)
                
                # Preserve directory timestamps
                preserve_timestamps(
                    output_path,
                    artifact.get('r_file_created_time'),
                    artifact.get('r_file_modified_time'),
                    artifact.get('r_file_accessed_time')
                )
                return True
            
            # Handle regular files
            with open(output_path, 'wb') as out_file:
                offset = 0
                chunk_size = 1024 * 1024  # 1MB chunks
                
                while offset < file_size:
                    available = min(chunk_size, file_size - offset)
                    try:
                        data = file_obj.read_random(offset, available)
                        if not data:
                            break
                        out_file.write(data)
                        offset += len(data)
                    except Exception as read_error:
                        logger.warning(f"Error reading file at offset {offset}: {str(read_error)}")
                        # Try to continue with next chunk
                        offset += chunk_size
                        if offset > file_size:
                            break
            
            logger.info(f"Exported file to {output_path}")
            
            # Preserve file timestamps
            preserve_timestamps(
                output_path,
                artifact.get('r_file_created_time'),
                artifact.get('r_file_modified_time'),
                artifact.get('r_file_accessed_time')
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Error exporting file: {str(e)}")
            return False
    
    def get_file_preview(self, artifact, max_size=1024*1024):
        """Get a preview of the file content."""
        if not artifact.get('r_file_recovered') or not artifact.get('r_file_addr'):
            return None
        
        try:
            file_obj = self.fs_info.open_meta(artifact['r_file_addr'])
            file_size = min(artifact['r_file_size'], max_size)
            
            try:
                data = file_obj.read_random(0, file_size)
                return data
            except Exception as read_error:
                logger.warning(f"Error reading file preview: {str(read_error)}")
                return None
                
        except Exception as e:
            logger.error(f"Error getting file preview: {str(e)}")
            return None
    
    def get_statistics(self):
        """Get statistics about the parsing process."""
        stats = self.stats.copy()
        
        # Add additional statistics
        stats['recoverable_files'] = len([a for a in self.artifacts if a['r_file_recovered']])
        stats['unrecoverable_files'] = len([a for a in self.artifacts if not a['r_file_recovered']])
        
        # File type statistics
        file_types = {}
        for artifact in self.artifacts:
            file_type = artifact.get('file_type', 'Unknown')
            if file_type not in file_types:
                file_types[file_type] = 0
            file_types[file_type] += 1
        
        stats['file_types'] = file_types
        
        return stats

# Worker threads for background tasks
class HashWorker(QThread):
    """Worker thread for calculating file hashes."""
    hash_ready = Signal(str, dict)
    
    def __init__(self, parser):
        super().__init__()
        self.parser = parser
        self.queue = []
        self.running = True
    
    def add_to_queue(self, artifact_id, artifact, hash_types):
        """Add an artifact to the hash calculation queue."""
        self.queue.append((artifact_id, artifact, hash_types))
        if not self.isRunning():
            self.start()
    
    def run(self):
        """Process the hash queue."""
        while self.running:
            if self.queue:
                artifact_id, artifact, hash_types = self.queue.pop(0)
                try:
                    # Calculate hashes
                    if artifact.get('r_file_recovered') and artifact.get('r_file_addr'):
                        hash_results = self.parser.calculate_file_hash(artifact['r_file_addr'], hash_types)
                        # Emit signal with hash results
                        self.hash_ready.emit(artifact_id, hash_results)
                except Exception as e:
                    logger.error(f"Error calculating hash: {str(e)}")
            
            # Sleep to prevent CPU hogging
            self.msleep(50)
    
    def stop(self):
        """Stop the worker thread."""
        self.running = False
        self.wait()

class ExportWorker(QThread):
    """Worker thread for exporting files with progress tracking and ETA."""
    progress_update = Signal(int, str, str)  # progress, message, eta
    export_complete = Signal(dict)
    
    def __init__(self, parser):
        super().__init__()
        self.parser = parser
        self.artifacts = []
        self.export_dir = ""
        self.hash_types = []
        self.generate_csv = False
        self.preserve_structure = False
        self.sid_hierarchy = False
        self.flat_export = False
        self.both_hierarchies = False
        self.overwrite_mode = "always"  # "always", "never", "ask"
        self.cancelled = False
        self.timestamp = ""
    
    def configure(self, artifacts, export_dir, hash_types, generate_csv, preserve_structure,
                  sid_hierarchy, flat_export, both_hierarchies, overwrite_mode):
        """Configure the export worker."""
        self.artifacts = artifacts
        self.export_dir = export_dir
        self.hash_types = hash_types
        self.generate_csv = generate_csv
        self.preserve_structure = preserve_structure
        self.sid_hierarchy = sid_hierarchy
        self.flat_export = flat_export
        self.both_hierarchies = both_hierarchies
        self.overwrite_mode = overwrite_mode
        self.cancelled = False
    
    def cancel(self):
        """Cancel the export operation."""
        self.cancelled = True
    
    def format_eta(self, seconds):
        """Format ETA in human readable format."""
        if seconds < 0 or seconds > 86400:  # More than a day
            return "Calculating..."
        if seconds < 60:
            return f"{int(seconds)}s remaining"
        elif seconds < 3600:
            mins = int(seconds // 60)
            secs = int(seconds % 60)
            return f"{mins}m {secs}s remaining"
        else:
            hours = int(seconds // 3600)
            mins = int((seconds % 3600) // 60)
            return f"{hours}h {mins}m remaining"
    
    def format_size(self, size):
        """Format file size."""
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size/1024:.1f} KB"
        elif size < 1024 * 1024 * 1024:
            return f"{size/(1024*1024):.1f} MB"
        else:
            return f"{size/(1024*1024*1024):.2f} GB"
    
    def _remove_duplicate_children(self, artifacts):
        """Remove duplicate exports - if folder is selected, don't export children separately."""
        if not artifacts:
            return artifacts
        
        # Get all selected folder paths
        folder_paths = set()
        for artifact in artifacts:
            if artifact.get('r_file_is_directory', False):
                folder_paths.add(artifact.get('original_path', ''))
        
        if not folder_paths:
            return artifacts  # No folders, nothing to deduplicate
        
        # Filter out children of selected folders
        filtered = []
        for artifact in artifacts:
            artifact_path = artifact.get('original_path', '')
            is_child_of_folder = False
            
            # Check if this artifact is a child of any selected folder
            for folder_path in folder_paths:
                if folder_path and artifact_path != folder_path:
                    if artifact_path.startswith(folder_path + '\\') or artifact_path.startswith(folder_path + '/'):
                        is_child_of_folder = True
                        break
            
            if not is_child_of_folder:
                filtered.append(artifact)
        
        return filtered
    
    def run(self):
        """Perform the export operation with progress tracking."""
        # Remove duplicates: if a folder is selected, don't export children separately
        artifacts_to_export = self._remove_duplicate_children(self.artifacts)
        
        total_files = len(artifacts_to_export)
        exported_files = 0
        failed_files = 0
        skipped_files = 0
        
        # Calculate total size for better ETA estimation
        total_size = sum(a.get('original_size', 0) for a in artifacts_to_export)
        
        # Use filtered list
        self.artifacts = artifacts_to_export
        processed_size = 0
        
        # Create Export subfolder with timestamp
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        export_folder_name = f"Export_{self.timestamp}"
        export_base_dir = os.path.join(self.export_dir, export_folder_name)
        os.makedirs(export_base_dir, exist_ok=True)
        
        # Prepare CSV/JSON data
        csv_data = []
        error_data = []  # Track failed exports with details
        
        # Track timing for ETA calculation
        start_time = time.time()
        file_times = []  # Track time per MB for adaptive ETA
        
        for i, artifact in enumerate(self.artifacts):
            if self.cancelled:
                break
            
            file_start_time = time.time()
            
            # Get file name from original path
            file_name = os.path.basename(artifact['original_path'])
            file_size = artifact.get('original_size', 0)
            
            # Calculate progress and ETA
            progress = int(((i + 1) / total_files) * 100)
            
            # Calculate ETA based on processed size and time
            elapsed_time = time.time() - start_time
            if processed_size > 0 and elapsed_time > 0:
                # Bytes per second
                speed = processed_size / elapsed_time
                remaining_size = total_size - processed_size
                if speed > 0:
                    eta_seconds = remaining_size / speed
                else:
                    eta_seconds = -1
            else:
                # Fallback: estimate based on file count
                if i > 0:
                    avg_time_per_file = elapsed_time / i
                    eta_seconds = avg_time_per_file * (total_files - i)
                else:
                    eta_seconds = -1
            
            eta_str = self.format_eta(eta_seconds)
            
            # Update status with detailed info
            status_msg = f"[{i+1}/{total_files}] {file_name} ({self.format_size(file_size)})"
            self.progress_update.emit(progress, status_msg, eta_str)
            
            # Create export path based on organization options (inside Export folder)
            if self.flat_export:
                export_path = os.path.join(export_base_dir, file_name)
            elif self.both_hierarchies:
                original_dir = os.path.dirname(artifact['original_path'])
                if len(original_dir) >= 2 and original_dir[1] == ':':
                    original_dir = original_dir[2:]
                original_dir = original_dir.lstrip("\\").lstrip("/")
                export_subdir = os.path.join(export_base_dir, artifact['sid'], original_dir)
                os.makedirs(export_subdir, exist_ok=True)
                export_path = os.path.join(export_subdir, file_name)
            elif self.preserve_structure:
                original_dir = os.path.dirname(artifact['original_path'])
                if len(original_dir) >= 2 and original_dir[1] == ':':
                    original_dir = original_dir[2:]
                original_dir = original_dir.lstrip("\\").lstrip("/")
                export_subdir = os.path.join(export_base_dir, original_dir)
                os.makedirs(export_subdir, exist_ok=True)
                export_path = os.path.join(export_subdir, file_name)
            elif self.sid_hierarchy:
                export_subdir = os.path.join(export_base_dir, artifact['sid'])
                os.makedirs(export_subdir, exist_ok=True)
                export_path = os.path.join(export_subdir, file_name)
            else:
                export_path = os.path.join(export_base_dir, file_name)
            
            # Handle duplicate file names
            if os.path.exists(export_path):
                if self.overwrite_mode == "always":
                    pass
                elif self.overwrite_mode == "never":
                    base, ext = os.path.splitext(export_path)
                    counter = 1
                    while os.path.exists(export_path):
                        export_path = f"{base}_{counter}{ext}"
                        counter += 1
                else:
                    skipped_files += 1
                    continue
            
            # Export file
            success = self.parser.export_file(artifact, export_path)
            
            # Update processed size
            processed_size += file_size
            
            if success:
                exported_files += 1
                
                # Calculate hashes if requested
                hash_results = {}
                if self.hash_types and not artifact.get('r_file_is_directory', False):
                    hash_results = self.parser.calculate_file_hash(artifact['r_file_addr'], self.hash_types)
                
                # Add to CSV/JSON data
                csv_row = {
                    'file_name': file_name,
                    'original_path': artifact['original_path'],
                    'original_size': artifact['original_size'],
                    'original_size_formatted': self.format_size(artifact['original_size']),
                    'deletion_time': artifact['deletion_time'].strftime('%Y-%m-%dT%H:%M:%SZ') if artifact['deletion_time'] else 'Unknown',
                    'sid': artifact['sid'],
                    'i_file_name': artifact.get('i_file_name', ''),
                    'r_file_name': artifact.get('r_file_name', ''),
                    'r_file_size': artifact.get('r_file_size', 0),
                    'r_file_size_formatted': self.format_size(artifact.get('r_file_size', 0)),
                    'export_path': os.path.normpath(export_path),
                    'file_type': artifact.get('file_type', 'Unknown'),
                    'version': artifact['version'],
                    'is_directory': artifact.get('r_file_is_directory', False),
                    'r_file_recovered': artifact.get('r_file_recovered', False),
                    'is_child_item': artifact.get('is_child_item', False),
                    'parent_folder_path': artifact.get('parent_folder_path', ''),
                    'relative_path_in_folder': artifact.get('relative_path_in_folder', ''),
                    'folder_level': artifact.get('folder_level', 0)
                }
                
                # Add timestamps if available
                for time_field in ['created_time', 'modified_time', 'accessed_time',
                                  'r_file_created_time', 'r_file_modified_time', 'r_file_accessed_time']:
                    if artifact.get(time_field):
                        csv_row[time_field] = artifact[time_field].strftime('%Y-%m-%dT%H:%M:%SZ')
                
                # Add hash values
                csv_row.update(hash_results)
                csv_data.append(csv_row)
                
                # If this is a folder, also add its children to the CSV report
                if artifact.get('r_file_is_directory', False):
                    try:
                        folder_contents = self.parser.scan_folder_contents(artifact)
                        for child in folder_contents:
                            child_name = os.path.basename(child.get('original_path', ''))
                            relative_dir = child.get('relative_path_in_folder', '')
                            is_child_dir = child.get('r_file_is_directory', False)
                            
                            # For directories: relative_path_in_folder already includes dir name
                            # For files: relative_path_in_folder is parent dir, need to add filename
                            if is_child_dir:
                                if relative_dir:
                                    child_export_path = os.path.join(export_path, relative_dir)
                                else:
                                    child_export_path = os.path.join(export_path, child_name)
                            else:
                                if relative_dir:
                                    child_export_path = os.path.join(export_path, relative_dir, child_name)
                                else:
                                    child_export_path = os.path.join(export_path, child_name)
                            child_hash = {}
                            if self.hash_types and not child.get('r_file_is_directory', False):
                                try:
                                    child_hash = self.parser.calculate_file_hash(child['r_file_addr'], self.hash_types)
                                except:
                                    pass
                            
                            child_row = {
                                'file_name': child_name,
                                'original_path': child.get('original_path', ''),
                                'original_size': child.get('original_size', 0),
                                'original_size_formatted': self.format_size(child.get('original_size', 0)),
                                'deletion_time': artifact['deletion_time'].strftime('%Y-%m-%dT%H:%M:%SZ') if artifact.get('deletion_time') else 'Unknown',
                                'sid': artifact['sid'],
                                'i_file_name': child.get('i_file_name', ''),
                                'r_file_name': child.get('r_file_name', ''),
                                'r_file_size': child.get('r_file_size', 0),
                                'r_file_size_formatted': self.format_size(child.get('r_file_size', 0)),
                                'export_path': os.path.normpath(child_export_path),
                                'file_type': child.get('file_type', 'Unknown'),
                                'version': artifact['version'],
                                'is_directory': child.get('r_file_is_directory', False),
                                'r_file_recovered': child.get('r_file_recovered', True),
                                'is_child_item': True,
                                'parent_folder_path': child.get('parent_folder_path', artifact['original_path']),
                                'relative_path_in_folder': child.get('relative_path_in_folder', ''),
                                'folder_level': child.get('folder_level', 1)
                            }
                            for time_field in ['created_time', 'modified_time', 'accessed_time',
                                              'r_file_created_time', 'r_file_modified_time', 'r_file_accessed_time']:
                                if child.get(time_field):
                                    child_row[time_field] = child[time_field].strftime('%Y-%m-%dT%H:%M:%SZ')
                            child_row.update(child_hash)
                            csv_data.append(child_row)
                            exported_files += 1
                    except Exception as e:
                        logger.warning(f"Could not add folder contents to report: {e}")
            else:
                failed_files += 1
                # Track error details for error report
                error_data.append({
                    'file_name': file_name,
                    'original_path': artifact['original_path'],
                    'original_size': artifact['original_size'],
                    'original_size_formatted': self.format_size(artifact['original_size']),
                    'sid': artifact['sid'],
                    'i_file_name': artifact.get('i_file_name', ''),
                    'r_file_name': artifact.get('r_file_name', ''),
                    'r_file_recovered': artifact.get('r_file_recovered', False),
                    'is_child_item': artifact.get('is_child_item', False),
                    'error_reason': 'Export failed - file may be corrupted or unreadable'
                })
        
        # Generate reports in the selected directory (not inside Export folder)
        csv_path = None
        json_path = None
        
        if csv_data and not self.cancelled:
            self.progress_update.emit(98, "Generating reports...", "Almost done")
            
            # Build export options for report
            export_options = {
                'export_timestamp': datetime.datetime.now(tz=datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                'export_folder': export_base_dir,
                'total_files_selected': total_files,
                'files_exported': exported_files,
                'files_failed': failed_files,
                'files_skipped': skipped_files,
                'total_size_bytes': total_size,
                'total_size_formatted': self.format_size(total_size),
                'organization': {
                    'flat_export': self.flat_export,
                    'preserve_structure': self.preserve_structure,
                    'sid_hierarchy': self.sid_hierarchy,
                    'both_hierarchies': self.both_hierarchies
                },
                'hash_types': self.hash_types,
                'overwrite_mode': self.overwrite_mode,
                'generate_csv': self.generate_csv
            }
            
            # Generate CSV report in selected directory with timestamp suffix
            csv_path = os.path.join(self.export_dir, f"export_report_{self.timestamp}.csv")
            try:
                with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                    fieldnames = ['file_name', 'original_path', 'original_size', 'original_size_formatted',
                                 'deletion_time', 'sid', 'i_file_name', 'r_file_name', 'r_file_size',
                                 'r_file_size_formatted', 'export_path', 'file_type', 'version', 'is_directory',
                                 'r_file_recovered', 'is_child_item', 'parent_folder_path',
                                 'relative_path_in_folder', 'folder_level',
                                 'created_time', 'modified_time', 'accessed_time',
                                 'r_file_created_time', 'r_file_modified_time', 'r_file_accessed_time']
                    
                    for hash_type in self.hash_types:
                        fieldnames.append(f"{hash_type}_hash")
                    
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
                    writer.writeheader()
                    
                    for row in csv_data:
                        writer.writerow(row)
            except Exception as e:
                logger.error(f"Error generating CSV report: {str(e)}")
                csv_path = None
            
            # Generate JSON report in selected directory with timestamp suffix
            json_path = os.path.join(self.export_dir, f"export_report_{self.timestamp}.json")
            try:
                json_report = {
                    'export_info': export_options,
                    'artifacts': csv_data,
                    'errors': error_data
                }
                
                with open(json_path, 'w', encoding='utf-8') as jsonfile:
                    json.dump(json_report, jsonfile, indent=2, ensure_ascii=False)
            except Exception as e:
                logger.error(f"Error generating JSON report: {str(e)}")
                json_path = None
        
        # Generate error CSV if there are failed exports
        error_csv_path = None
        if error_data and not self.cancelled:
            error_csv_path = os.path.join(self.export_dir, f"export_errors_{self.timestamp}.csv")
            try:
                with open(error_csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                    fieldnames = ['file_name', 'original_path', 'original_size', 'original_size_formatted',
                                 'sid', 'i_file_name', 'r_file_name', 'r_file_recovered',
                                 'is_child_item', 'error_reason']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
                    writer.writeheader()
                    for row in error_data:
                        writer.writerow(row)
            except Exception as e:
                logger.error(f"Error generating error CSV: {str(e)}")
                error_csv_path = None
        
        self.progress_update.emit(100, "Export complete!", "Done")
        
        # Log detailed export summary
        logger.info("="*60)
        logger.info("EXPORT SUMMARY")
        logger.info("="*60)
        logger.info(f"Export completed at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info(f"Destination folder: {export_base_dir}")
        logger.info(f"Total files selected: {total_files}")
        logger.info(f"Successfully exported: {exported_files} files")
        logger.info(f"Failed exports: {failed_files} files")
        logger.info(f"Skipped files: {skipped_files} files")
        logger.info(f"Total size: {self.format_size(total_size)}")
        if csv_path:
            logger.info(f"CSV report: {csv_path}")
        if json_path:
            logger.info(f"JSON report: {json_path}")
        if error_csv_path:
            logger.info(f"Error report: {error_csv_path}")
        if self.cancelled:
            logger.info("Export was CANCELLED by user")
        logger.info("="*60)
        
        # Emit completion signal with results
        self.export_complete.emit({
            'exported': exported_files,
            'failed': failed_files,
            'skipped': skipped_files,
            'total': total_files,
            'csv_path': csv_path,
            'json_path': json_path,
            'error_csv_path': error_csv_path,
            'export_folder': export_base_dir,
            'timestamp': self.timestamp,
            'cancelled': self.cancelled
        })

class ReportGenerationWorker(QThread):
    """Worker thread for generating reports."""
    progress_update = Signal(int, str, str)  # progress, message, eta
    report_complete = Signal(dict)
    
    def __init__(self, parser, artifacts, report_path, hash_types, include_recursive=False, timezone="UTC"):
        super().__init__()
        self.parser = parser
        self.artifacts = artifacts
        self.report_path = report_path
        self.hash_types = hash_types
        self.include_recursive = include_recursive
        self.timezone = timezone
        self.start_time = None
    
    def run(self):
        """Generate the report."""
        import time
        self.start_time = time.time()
        
        try:
            # Collect all artifacts including recursive folder contents
            all_items_to_hash = []
            
            # First pass: collect all items that need hashing
            self.progress_update.emit(5, "Collecting items for hashing...", "Calculating...")
            for artifact in self.artifacts:
                all_items_to_hash.append(artifact)
                # If recursive is enabled, also collect folder contents
                if self.include_recursive and artifact.get('r_file_is_directory'):
                    folder_contents = self.parser.scan_folder_contents(artifact)
                    all_items_to_hash.extend(folder_contents)
                    # Store folder contents in artifact for later CSV writing
                    artifact['_folder_contents'] = folder_contents
            
            # Calculate hashes if requested
            if self.hash_types and all_items_to_hash:
                total_items = len(all_items_to_hash)
                for i, item in enumerate(all_items_to_hash):
                    progress = int((i / total_items) * 80) + 5  # Use 5-85% for hash calculation
                    file_name = os.path.basename(item.get('original_path', ''))
                    eta = self._calculate_eta(progress)
                    self.progress_update.emit(progress, f"Calculating hashes for {file_name}...", eta)
                    
                    if item.get('r_file_recovered') and not item.get('r_file_is_directory', False):
                        hash_results = self.parser.calculate_file_hash(item.get('r_file_addr'), self.hash_types)
                        # Update item with hash values
                        item.update(hash_results)
            
            # Generate CSV - pass the artifacts with computed hashes
            self.progress_update.emit(90, "Writing CSV file...", "Almost done...")
            success = self.parser.save_to_csv(self.report_path, selected_artifacts=self.artifacts,
                                            hash_types=self.hash_types, 
                                            include_recursive=self.include_recursive,
                                            timezone=self.timezone,
                                            precomputed_folder_contents=True)
            
            self.progress_update.emit(100, "Report generation complete.", "Done")
            
            if success:
                self.report_complete.emit({
                    'success': True,
                    'path': self.report_path,
                    'error': None
                })
            else:
                self.report_complete.emit({
                    'success': False,
                    'path': None,
                    'error': 'Failed to write CSV file'
                })
                
        except Exception as e:
            self.report_complete.emit({
                'success': False,
                'path': None,
                'error': str(e)
            })
    
    def _calculate_eta(self, progress):
        """Calculate estimated time remaining."""
        import time
        if progress <= 0 or self.start_time is None:
            return "Calculating..."
        elapsed = time.time() - self.start_time
        if elapsed <= 0:
            return "Calculating..."
        total_estimated = elapsed / (progress / 100)
        remaining = total_estimated - elapsed
        if remaining < 60:
            return f"ETA: {int(remaining)}s"
        elif remaining < 3600:
            return f"ETA: {int(remaining / 60)}m {int(remaining % 60)}s"
        else:
            return f"ETA: {int(remaining / 3600)}h {int((remaining % 3600) / 60)}m"

class LoadImageThread(QThread):
    """Thread for loading an image and detecting partitions."""
    progress_update = Signal(int, str)
    partitions_ready = Signal(list)
    
    def __init__(self, parser):
        super().__init__()
        self.parser = parser
    
    def run(self):
        """Run the thread."""
        try:
            # Open the image
            self.progress_update.emit(10, "Opening image...")
            self.parser.open_image()
            
            # Detect partitions
            self.progress_update.emit(50, "Detecting partitions...")
            self.parser.detect_partitions()
            
            # Emit partitions
            self.progress_update.emit(100, "Partitions detected.")
            self.partitions_ready.emit(self.parser.partitions)
            
        except Exception as e:
            logger.error(f"Error loading image: {str(e)}")
            self.progress_update.emit(0, f"Error: {str(e)}")
            self.partitions_ready.emit([])

class ProcessPartitionThread(QThread):
    """Thread for processing a partition."""
    progress_update = Signal(int, str)
    artifacts_ready = Signal(list)
    
    def __init__(self, parser, partition_index):
        super().__init__()
        self.parser = parser
        self.partition_index = partition_index
    
    def run(self):
        """Run the thread."""
        try:
            # Select partition
            self.progress_update.emit(10, "Selecting partition...")
            self.parser.select_partition(self.partition_index)
            
            # Find Recycle Bin
            self.progress_update.emit(30, "Searching for Recycle Bin...")
            recycle_bin_path = self.parser.find_recycle_bin()
            
            if not recycle_bin_path:
                self.progress_update.emit(0, "Recycle Bin not found.")
                self.artifacts_ready.emit([])
                return
            
            # Collect SID directories
            self.progress_update.emit(50, "Collecting SID directories...")
            sid_dirs = self.parser.collect_sid_directories(recycle_bin_path)
            
            if not sid_dirs:
                self.progress_update.emit(0, "No SID directories found.")
                self.artifacts_ready.emit([])
                return
            
            # Collect $I files
            self.progress_update.emit(70, "Collecting deleted files...")
            i_files = self.parser.collect_i_files(sid_dirs)
            
            if not i_files:
                self.progress_update.emit(0, "No deleted files found.")
                self.artifacts_ready.emit([])
                return
            
            # Process $I files
            self.progress_update.emit(90, "Processing deleted files...")
            self.parser.process_i_files(i_files)
            
            # Emit artifacts
            self.progress_update.emit(100, "Processing complete.")
            self.artifacts_ready.emit(self.parser.artifacts)
            
        except Exception as e:
            logger.error(f"Error processing partition: {str(e)}")
            self.progress_update.emit(0, f"Error: {str(e)}")
            self.artifacts_ready.emit([])

class FolderContentWorker(QThread):
    """Worker thread for loading folder contents."""
    content_ready = Signal(list)
    
    def __init__(self, parser, artifact):
        super().__init__()
        self.parser = parser
        self.artifact = artifact
    
    def run(self):
        """Load folder contents."""
        try:
            contents = self.parser.scan_folder_contents(self.artifact)
            self.content_ready.emit(contents)
        except Exception as e:
            logger.error(f"Error loading folder contents: {str(e)}")
            self.content_ready.emit([])

# Models for data representation
class FileSystemModel(QStandardItemModel):
    """Model for representing the file system structure."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHorizontalHeaderLabels(["Name", "Files"])
        self.root_item = self.invisibleRootItem()
    
    def populate_from_artifacts(self, artifacts, tree_view_mode="sid"):
        """Populate the model from artifacts."""
        self.clear()
        self.setHorizontalHeaderLabels(["Name", "Files"])
        
        if tree_view_mode == "sid":
            self.populate_by_sid(artifacts)
        else:
            # Implement path-based view if needed
            self.populate_by_sid(artifacts)  # Fallback to SID view
    
    def populate_by_sid(self, artifacts):
        """Populate the model organized by SID."""
        # Group artifacts by SID
        sid_groups = {}
        for artifact in artifacts:
            sid = artifact['sid']
            if sid not in sid_groups:
                sid_groups[sid] = []
            sid_groups[sid].append(artifact)
        
        # Count only recoverable artifacts for display
        total_recoverable = sum(1 for a in artifacts if a.get('r_file_recovered', False))
        
        # Create recycle bin root item with checkbox
        recycle_bin_item = QStandardItem(QApplication.style().standardIcon(QStyle.SP_TrashIcon), "$Recycle.Bin")
        recycle_bin_item.setData("root", Qt.UserRole)
        recycle_bin_count_item = QStandardItem(str(total_recoverable))
        recycle_bin_count_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.appendRow([recycle_bin_item, recycle_bin_count_item])
        
        # Add SID folders
        for sid, items in sid_groups.items():
            sid_recoverable = sum(1 for a in items if a.get('r_file_recovered', False))
            sid_item = QStandardItem(QApplication.style().standardIcon(QStyle.SP_DirIcon), sid)
            sid_item.setData(f"sid:{sid}", Qt.UserRole)
            sid_count_item = QStandardItem(str(sid_recoverable))
            sid_count_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            recycle_bin_item.appendRow([sid_item, sid_count_item])
            
            # Group files by original path
            path_structure = {}
            
            # Build path structure
            for artifact in items:
                original_path = artifact['original_path']
                drive, path = os.path.splitdrive(original_path)
                
                # Skip if no path
                if not path:
                    continue
                
                # Get directory path and filename
                dir_path = os.path.dirname(path)
                file_name = os.path.basename(path)
                
                # Create drive entry if it doesn't exist
                if drive not in path_structure:
                    path_structure[drive] = {'files': [], 'dirs': {}}
                
                # Navigate through directory structure
                current = path_structure[drive]
                
                # Split directory path into components
                if dir_path:
                    components = [p for p in dir_path.split('\\') if p]
                    for component in components:
                        if component not in current['dirs']:
                            current['dirs'][component] = {'files': [], 'dirs': {}}
                        current = current['dirs'][component]
                
                # Add file to current directory
                current['files'].append(artifact)
            
            # Add drives to SID
            for drive, drive_data in path_structure.items():
                drive_name = drive if drive else "Unknown Drive"
                drive_item = QStandardItem(QApplication.style().standardIcon(QStyle.SP_DriveHDIcon), drive_name)
                drive_item.setData(f"drive:{sid}:{drive}", Qt.UserRole)
                
                # Count only RECOVERABLE files in drive
                total_files = sum(1 for f in drive_data['files'] if f.get('r_file_recovered', False))
                for dir_data in drive_data['dirs'].values():
                    total_files += self.count_files_recursive(dir_data)
                
                drive_count_item = QStandardItem(str(total_files))
                drive_count_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                sid_item.appendRow([drive_item, drive_count_item])
                
                # Add files directly in drive (non-recoverable items are always treated as files)
                for artifact in drive_data['files']:
                    file_name = os.path.basename(artifact['original_path'])
                    file_item = QStandardItem(self.get_file_icon(artifact), file_name)
                    # Always use file: prefix - non-recoverable items can't be browsed
                    file_item.setData(f"file:{artifact['i_file_name']}", Qt.UserRole)
                    # Non-recoverable items show "-" instead of count
                    count_text = "-" if not artifact.get('r_file_recovered', False) else "1"
                    file_count_item = QStandardItem(count_text)
                    file_count_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                    drive_item.appendRow([file_item, file_count_item])
                
                # Add directories
                self.add_directories_recursive(drive_item, drive_data['dirs'], f"dir:{sid}:{drive}")
    
    def add_directories_recursive(self, parent_item, dirs, parent_path):
        """Add directories recursively to the model."""
        for dir_name, dir_data in dirs.items():
            # Count only RECOVERABLE files in directory (including subdirectories)
            total_files = sum(1 for f in dir_data['files'] if f.get('r_file_recovered', False))
            for subdir_data in dir_data['dirs'].values():
                total_files += self.count_files_recursive(subdir_data)
            
            # Check if there are ANY files (recoverable or not) to decide visibility
            any_files = len(dir_data['files']) > 0 or any(
                len(sd['files']) > 0 or sd['dirs'] for sd in dir_data['dirs'].values()
            )
            
            # Skip truly empty directories (no files at all)
            if not any_files and not dir_data['dirs']:
                continue
            
            # Create directory item
            dir_item = QStandardItem(QApplication.style().standardIcon(QStyle.SP_DirIcon), dir_name)
            dir_path = f"{parent_path}\\{dir_name}"
            dir_item.setData(dir_path, Qt.UserRole)
            
            dir_count_item = QStandardItem(str(total_files))
            dir_count_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            parent_item.appendRow([dir_item, dir_count_item])
            
            # Add files in directory (non-recoverable items are always treated as files)
            for artifact in dir_data['files']:
                file_name = os.path.basename(artifact['original_path'])
                file_item = QStandardItem(self.get_file_icon(artifact), file_name)
                # Always use file: prefix - non-recoverable items can't be browsed
                file_item.setData(f"file:{artifact['i_file_name']}", Qt.UserRole)
                # Non-recoverable items show "-" instead of count
                count_text = "-" if not artifact.get('r_file_recovered', False) else "1"
                file_count_item = QStandardItem(count_text)
                file_count_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                dir_item.appendRow([file_item, file_count_item])
            
            # Add subdirectories (only non-empty ones will be added due to recursion)
            self.add_directories_recursive(dir_item, dir_data['dirs'], dir_path)
    
    def count_files_recursive(self, dir_data):
        """Count only RECOVERABLE files recursively in a directory structure."""
        # Only count recoverable files
        count = sum(1 for f in dir_data['files'] if f.get('r_file_recovered', False))
        for subdir_data in dir_data['dirs'].values():
            count += self.count_files_recursive(subdir_data)
        return count
    
    def get_file_icon(self, artifact):
        """Get an appropriate icon for a file based on its type and recovery status."""
        # Use cross/warning icon for non-recoverable items
        if not artifact.get('r_file_recovered', False):
            return QApplication.style().standardIcon(QStyle.SP_BrowserStop)  # Cross/stop icon
        
        if artifact.get('r_file_is_directory', False):
            return QIcon.fromTheme("folder", QApplication.style().standardIcon(QStyle.SP_DirIcon))
        
        file_ext = artifact.get('file_ext', '').lower()
        file_type = artifact.get('file_type', 'Other')
        
        if file_type == "Image":
            return QIcon.fromTheme("image-x-generic", QApplication.style().standardIcon(QStyle.SP_FileDialogDetailedView))
        elif file_type == "Document":
            if file_ext == '.pdf':
                return QIcon.fromTheme("application-pdf", QApplication.style().standardIcon(QStyle.SP_FileDialogDetailedView))
            else:
                return QIcon.fromTheme("text-x-generic", QApplication.style().standardIcon(QStyle.SP_FileDialogDetailedView))
        elif file_type == "Video":
            return QIcon.fromTheme("video-x-generic", QApplication.style().standardIcon(QStyle.SP_MediaPlay))
        elif file_type == "Audio":
            return QIcon.fromTheme("audio-x-generic", QApplication.style().standardIcon(QStyle.SP_MediaVolume))
        elif file_type == "Archive":
            return QIcon.fromTheme("package-x-generic", QApplication.style().standardIcon(QStyle.SP_DirLinkIcon))
        elif file_type == "Executable":
            return QIcon.fromTheme("application-x-executable", QApplication.style().standardIcon(QStyle.SP_DriveFDIcon))
        else:
            return QIcon.fromTheme("text-x-generic", QApplication.style().standardIcon(QStyle.SP_FileIcon))

class ResponsiveGridWidget(QWidget):
    """Responsive grid widget that reflows tiles like Windows Explorer."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.cards = []
        self.card_width = 150
        self.card_spacing = 12
        
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(12, 12, 12, 12)
        self.main_layout.setSpacing(0)
        
        self.grid_container = QWidget()
        self.grid_layout = QGridLayout(self.grid_container)
        self.grid_layout.setSpacing(self.card_spacing)
        self.grid_layout.setContentsMargins(0, 0, 0, 0)
        self.grid_layout.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        
        self.main_layout.addWidget(self.grid_container)
        self.main_layout.addStretch()
    
    def clear_cards(self):
        """Clear all cards from the grid."""
        for card in self.cards:
            card.hide()  # Hide first to prevent flash
            card.deleteLater()
        self.cards.clear()
    
    def add_card(self, card):
        """Add a card to the grid."""
        self.cards.append(card)
    
    def relayout_cards(self):
        """Relayout all cards based on current width."""
        # Remove all widgets from layout without deleting them
        for i in reversed(range(self.grid_layout.count())):
            item = self.grid_layout.itemAt(i)
            if item and item.widget():
                self.grid_layout.removeWidget(item.widget())
        
        available_width = self.width() - 24  # Account for margins (12+12)
        card_total_width = self.card_width + self.card_spacing
        columns = max(1, available_width // card_total_width)
        
        row, col = 0, 0
        for card in self.cards:
            self.grid_layout.addWidget(card, row, col)
            col += 1
            if col >= columns:
                col = 0
                row += 1
    
    def resizeEvent(self, event):
        """Handle resize to reflow cards."""
        super().resizeEvent(event)
        self.relayout_cards()


class CalendarDialog(QDialog):
    """Calendar dialog for date selection."""
    def __init__(self, parent=None, current_date=None):
        super().__init__(parent)
        self.setWindowTitle("Select Date")
        self.setModal(True)
        self.setMinimumSize(300, 250)
        
        from PySide6.QtWidgets import QCalendarWidget
        from PySide6.QtCore import QDate
        
        layout = QVBoxLayout(self)
        
        self.calendar = QCalendarWidget()
        self.calendar.setStyleSheet("""
            QCalendarWidget {
                background-color: white;
            }
            QCalendarWidget QToolButton {
                color: #1e293b;
                background-color: #f1f5f9;
                border: none;
                border-radius: 4px;
                padding: 4px;
                margin: 2px;
            }
            QCalendarWidget QToolButton:hover {
                background-color: #e2e8f0;
            }
            QCalendarWidget QMenu {
                background-color: white;
                color: #1e293b;
            }
            QCalendarWidget QSpinBox {
                background-color: white;
                color: #1e293b;
                border: 1px solid #cbd5e1;
            }
            QCalendarWidget QWidget#qt_calendar_navigationbar {
                background-color: #f1f5f9;
            }
            QCalendarWidget QTableView {
                background-color: white;
                selection-background-color: #0078d4;
                selection-color: white;
            }
        """)
        if current_date:
            self.calendar.setSelectedDate(current_date)
        self.calendar.clicked.connect(self.date_selected)
        layout.addWidget(self.calendar)
        
        self.selected_date = current_date if current_date else QDate.currentDate()
    
    def date_selected(self, date):
        self.selected_date = date
        self.accept()


class DatePickerWidget(QWidget):
    """Custom date picker widget with calendar icon button."""
    dateChanged = Signal(object)
    
    def __init__(self, initial_date=None, parent=None):
        super().__init__(parent)
        from PySide6.QtCore import QDate
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Date display field
        self.date_field = QLineEdit()
        self.current_date = initial_date if initial_date else QDate.currentDate()
        self.date_field.setText(self.current_date.toString("yyyy-MM-dd"))
        self.date_field.setReadOnly(True)
        self.date_field.setMinimumHeight(32)
        self.date_field.setStyleSheet("""
            QLineEdit {
                border: 1px solid #cbd5e1;
                border-right: none;
                border-radius: 6px 0 0 6px;
                padding: 6px 12px;
                background-color: #ffffff;
                color: #1e293b;
                font-size: 13px;
            }
        """)
        layout.addWidget(self.date_field)
        
        # Calendar icon button
        self.calendar_btn = QPushButton("📅")
        self.calendar_btn.setFixedSize(36, 32)
        self.calendar_btn.setCursor(QCursor(Qt.PointingHandCursor))
        self.calendar_btn.setStyleSheet("""
            QPushButton {
                font-size: 16px;
                background-color: #0078d4;
                color: white;
                border: 1px solid #0078d4;
                border-radius: 0 6px 6px 0;
            }
            QPushButton:hover {
                background-color: #005a9e;
                border-color: #005a9e;
            }
            QPushButton:pressed {
                background-color: #004578;
            }
        """)
        self.calendar_btn.clicked.connect(self.show_calendar)
        layout.addWidget(self.calendar_btn)
    
    def show_calendar(self):
        dialog = CalendarDialog(self, self.current_date)
        if dialog.exec():
            self.current_date = dialog.selected_date
            self.date_field.setText(self.current_date.toString("yyyy-MM-dd"))
            self.dateChanged.emit(self.current_date)
    
    def date(self):
        return self.current_date
    
    def setDate(self, date):
        self.current_date = date
        self.date_field.setText(date.toString("yyyy-MM-dd"))


class FileListModel(QStandardItemModel):
    """Model for representing the file list."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.artifacts = []
        self.filtered_artifacts = []
        self.current_sort = {"column": "deletion_time", "order": "descending"}
    
    def set_artifacts(self, artifacts):
        """Set the artifacts to display."""
        self.artifacts = artifacts
        self.filtered_artifacts = artifacts
        self.sort_artifacts()
    
    def filter_artifacts(self, filter_text="", filter_type="All"):
        """Filter artifacts by text and type."""
        if not filter_text and filter_type == "All":
            self.filtered_artifacts = self.artifacts
        else:
            filtered = []
            for artifact in self.artifacts:
                # Check file type filter
                if filter_type != "All" and artifact.get('file_type', 'Other') != filter_type:
                    continue
                
                # Check text filter
                if filter_text:
                    file_name = os.path.basename(artifact['original_path']).lower()
                    path = artifact['original_path'].lower()
                    if filter_text.lower() not in file_name and filter_text.lower() not in path:
                        continue
                
                filtered.append(artifact)
            
            self.filtered_artifacts = filtered
        
        self.sort_artifacts()
    
    def sort_artifacts(self):
        """Sort artifacts based on current sort settings."""
        column = self.current_sort["column"]
        reverse = self.current_sort["order"] == "descending"
        
        # Special handling for file name sorting
        if column == "name":
            self.filtered_artifacts = sorted(
                self.filtered_artifacts,
                key=lambda a: os.path.basename(a.get('original_path', '')).lower(),
                reverse=reverse
            )
        else:
            # For other columns, sort by the column value
            self.filtered_artifacts = sorted(
                self.filtered_artifacts,
                key=lambda a: a.get(column, 0) or 0,
                reverse=reverse
            )
    
    def set_sort(self, column, order):
        """Set the sort column and order."""
        self.current_sort = {"column": column, "order": order}
        self.sort_artifacts()

class FileItemDelegate(QStyledItemDelegate):
    """Delegate for rendering file items in the list view."""
    
    def __init__(self, parent=None, datetime_formatter=None):
        super().__init__(parent)
        self.datetime_formatter = datetime_formatter
    
    def get_file_type_icon(self, file_ext, is_directory=False, dark_mode=False):
        """Get an appropriate icon for a file based on its extension."""
        if is_directory:
            # Use a more visible folder icon - SP_DirOpenIcon is often more visible
            return QIcon.fromTheme("folder", QApplication.style().standardIcon(QStyle.SP_DirOpenIcon))
        
        file_ext = file_ext.lower() if file_ext else ''
        
        # Use QFileIconProvider to get system icons for file types
        try:
            # Create a temporary file with the extension to get its icon
            temp_path = os.path.join(tempfile.gettempdir(), f"temp{file_ext}")
            with open(temp_path, 'w') as f:
                pass
            file_info = QFileInfo(temp_path)
            icon_provider = QFileIconProvider()
            icon = icon_provider.icon(file_info)
            
            # Clean up
            os.remove(temp_path)
            return icon
        except:
            # Fallback to built-in icons
            if file_ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp']:
                return QIcon.fromTheme("image-x-generic", QApplication.style().standardIcon(QStyle.SP_FileDialogDetailedView))
            elif file_ext in ['.doc', '.docx', '.pdf', '.txt', '.rtf', '.odt']:
                return QIcon.fromTheme("text-x-generic", QApplication.style().standardIcon(QStyle.SP_FileDialogDetailedView))
            elif file_ext in ['.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv']:
                return QIcon.fromTheme("video-x-generic", QApplication.style().standardIcon(QStyle.SP_MediaPlay))
            elif file_ext in ['.mp3', '.wav', '.ogg', '.flac', '.aac']:
                return QIcon.fromTheme("audio-x-generic", QApplication.style().standardIcon(QStyle.SP_MediaVolume))
            elif file_ext in ['.zip', '.rar', '.7z', '.tar', '.gz']:
                return QIcon.fromTheme("package-x-generic", QApplication.style().standardIcon(QStyle.SP_DirLinkIcon))
            elif file_ext in ['.exe', '.dll', '.bat', '.cmd', '.msi']:
                return QIcon.fromTheme("application-x-executable", QApplication.style().standardIcon(QStyle.SP_DriveFDIcon))
            else:
                return QIcon.fromTheme("text-x-generic", QApplication.style().standardIcon(QStyle.SP_FileIcon))
    
    def paint(self, painter, option, index):
        """Paint the item."""
        # Get artifact data
        artifact = index.data(Qt.UserRole)
        if not artifact:
            return super().paint(painter, option, index)
        
        # Set up the item area
        rect = option.rect
        
        # Draw selection background if selected
        if option.state & QStyle.State_Selected:
            painter.fillRect(rect, option.palette.highlight())
        
        # Draw file icon
        icon_rect = QRect(rect.left() + 5, rect.top() + 5, 64, 64)
        
        # Draw file type icon
        file_ext = artifact.get('file_ext', '').lower()
        is_directory = artifact.get('r_file_is_directory', False)
        icon = self.get_file_type_icon(file_ext, is_directory)
        icon.paint(painter, icon_rect)
        
        # Draw file name
        file_name = os.path.basename(artifact['original_path'])
        name_rect = QRect(rect.left() + 80, rect.top() + 5, rect.width() - 85, 20)
        
        # Set text color based on selection state
        if option.state & QStyle.State_Selected:
            painter.setPen(option.palette.highlightedText().color())
        else:
            painter.setPen(option.palette.text().color())
        
        # Use bold font for file name
        font = painter.font()
        font.setBold(True)
        painter.setFont(font)
        status_reserved_width = 110
        name_rect = QRect(rect.left() + 80, rect.top() + 5, rect.width() - 80 - status_reserved_width, 20)
        elided_name = painter.fontMetrics().elidedText(file_name, Qt.ElideMiddle, max(0, name_rect.width()))
        painter.drawText(name_rect, Qt.AlignLeft | Qt.AlignVCenter, elided_name)
        
        # Reset font for details
        font.setBold(False)
        painter.setFont(font)
        
        details_width = max(0, rect.width() - 80 - status_reserved_width)
        
        # Draw file size
        size_text = self.format_file_size(artifact['original_size'])
        size_rect = QRect(rect.left() + 80, rect.top() + 25, min(120, details_width), 20)
        painter.drawText(size_rect, Qt.AlignLeft | Qt.AlignVCenter, size_text)
        
        # Draw deletion time with timezone
        if artifact.get('deletion_time'):
            if self.datetime_formatter:
                date_text = self.datetime_formatter(artifact['deletion_time'])
            else:
                date_text = artifact['deletion_time'].strftime("%d-%b-%Y %H:%M")
        else:
            date_text = "Unknown date"
        date_rect = QRect(rect.left() + 80, rect.top() + 45, details_width, 20)
        elided_date = painter.fontMetrics().elidedText(date_text, Qt.ElideRight, max(0, date_rect.width()))
        painter.drawText(date_rect, Qt.AlignLeft | Qt.AlignVCenter, elided_date)
        
        # Draw recovery status - positioned relative to right edge for responsiveness
        status_width = 100
        status_rect = QRect(rect.right() - status_width - 5, rect.top() + (rect.height() - 20) // 2, status_width, 20)
        if artifact['r_file_recovered']:
            painter.setPen(QColor(0, 150, 0))  # Green for recoverable
            status_text = "Recoverable"
        else:
            painter.setPen(QColor(200, 0, 0))  # Red for not recoverable
            status_text = "Not recoverable"
        painter.drawText(status_rect, Qt.AlignRight | Qt.AlignVCenter, status_text)

    def sizeHint(self, option, index):
        """Return the size hint for the item."""
        return QSize(option.rect.width(), 74)

    def format_file_size(self, size):
        """Format file size in human-readable form."""
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size/1024:.1f} KB"
        elif size < 1024 * 1024 * 1024:
            return f"{size/(1024*1024):.1f} MB"
        else:
            return f"{size/(1024*1024*1024):.1f} GB"

class ElidedLabel(QLabel):
    def __init__(self, text="", parent=None, elide_mode=Qt.ElideMiddle):
        super().__init__("", parent)
        self._full_text = ""
        self._elide_mode = elide_mode
        self.setMinimumWidth(1)
        self.setText(text)

    def setText(self, text):
        self._full_text = text if text is not None else ""
        self._update_elided_text()

    def fullText(self):
        return self._full_text

    def setElideMode(self, mode):
        self._elide_mode = mode
        self._update_elided_text()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._update_elided_text()

    def _update_elided_text(self):
        width = self.contentsRect().width()
        if width <= 0:
            width = 200
        elided = self.fontMetrics().elidedText(self._full_text, self._elide_mode, max(0, width))
        super().setText(elided)

class MainWindow(QMainWindow):
    """Main window for the Recycle Bin Forensic Explorer."""
    
    def __init__(self):
        super().__init__()
        
        # Set window properties
        self.setWindowTitle("Recycle Bin Forensic Explorer v1.0")
        self.setMinimumSize(1200, 800)
        self.resize(1400, 900)
        
        # Set application icon
        self.setWindowIcon(QIcon.fromTheme("user-trash-full", QApplication.style().standardIcon(QStyle.SP_TrashIcon)))
        
        # Initialize variables
        self.parser = None
        self.image_path = None
        self.current_partition = None
        self.artifacts = []
        self.selected_artifacts = []
        self.current_displayed_artifacts = []
        self.current_tree_context = "root"
        self.current_folder = None
        self.current_view_mode = "tiles"  # "tiles" or "list"
        self.current_page = 0
        self.current_filtered_count = 0
        self.folder_navigation_stack = []  # For breadcrumb navigation
        self.ignore_background_results = False
        self.is_dark_mode = False
        self.settings = QSettings("RecycleBinForensicExplorer", "RecycleBinForensics")
        
        # Timezone setting - default to UTC
        self.current_timezone = "UTC"
        self.available_timezones = [
            "UTC", "US/Eastern", "US/Central", "US/Mountain", "US/Pacific",
            "Europe/London", "Europe/Paris", "Europe/Berlin", "Europe/Moscow",
            "Asia/Tokyo", "Asia/Shanghai", "Asia/Kolkata", "Asia/Dubai",
            "Australia/Sydney", "Pacific/Auckland"
        ]
        
        # Partition cache to avoid re-processing
        self.partition_cache = {}  # {partition_index: artifacts_list}
        self.is_processing_partition = False  # Prevent duplicate processing
        
        # Initialize worker threads
        self.hash_worker = None
        self.export_worker = None
        self.folder_worker = None
        
        # Set up UI
        self.setup_ui()
        self.load_ui_settings()
    
    def setup_ui(self):
        """Set up the user interface."""
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create main layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(15)
        
        # Create toolbar
        self.create_toolbar()

        self.create_menu_bar()
        
        # Create splitter for main content
        self.splitter = QSplitter(Qt.Horizontal)
        main_layout.addWidget(self.splitter)
        
        # Create left panel (directory tree)
        self.create_left_panel()
        
        # Create right panel (file view)
        self.create_right_panel()
        
        # Set initial splitter sizes
        self.splitter.setSizes([350, 850])
        
        # Create status bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)

        self.dataset_status_label = ElidedLabel("", elide_mode=Qt.ElideRight)
        self.dataset_status_label.setStyleSheet("padding: 0 10px; background: transparent;")
        self.statusBar.addPermanentWidget(self.dataset_status_label)

        self.selection_status_label = QLabel("")
        self.selection_status_label.setStyleSheet("padding: 0 10px; background: transparent;")
        self.statusBar.addPermanentWidget(self.selection_status_label)
        
        # Create progress bar in status bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(300)
        self.progress_bar.setVisible(False)
        self.statusBar.addPermanentWidget(self.progress_bar)
        
        # Set initial status
        self.statusBar.showMessage("Ready. Open an E01 image to begin forensic analysis.")
        self.update_persistent_status()
    
    def create_toolbar(self):
        """Create the modern toolbar with action buttons."""
        self.toolbar = QToolBar("Main Toolbar")
        self.toolbar.setObjectName("MainToolbar")  # Fix QMainWindow::saveState() warning
        self.toolbar.setIconSize(QSize(32, 32))
        self.toolbar.setMovable(False)
        self.toolbar.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)
        self.addToolBar(self.toolbar)
        
        # Open E01 Image button
        self.open_action = QAction(
            QIcon.fromTheme("document-open", QApplication.style().standardIcon(QStyle.SP_DirOpenIcon)), 
            "Open Image", self
        )
        self.open_action.setShortcut(QKeySequence.Open)
        self.open_action.triggered.connect(self.open_image)
        self.toolbar.addAction(self.open_action)
        
        # Partition selector
        self.toolbar.addSeparator()
        self.partition_label = QLabel("Partition:")
        self.partition_label.setObjectName("partitionLabel")
        self.toolbar.addWidget(self.partition_label)
        
        self.partition_combo = QComboBox()
        self.partition_combo.setMinimumWidth(250)
        self.partition_combo.setPlaceholderText("Select a partition...")
        self.partition_combo.setEnabled(False)
        self.partition_combo.setStyleSheet("""
            QComboBox {
                border: 1px solid #d0d7de;
                border-radius: 6px;
                padding: 5px 28px 5px 10px;
                background-color: #f6f8fa;
                font-weight: 600;
                color: #24292f;
                min-height: 20px;
            }
            QComboBox:hover {
                background-color: #f3f4f6;
                border-color: #afb8c1;
            }
            QComboBox:disabled {
                background-color: #f6f8fa;
                color: #8c959f;
                border: 1px solid #d8dee4;
            }
            QComboBox QAbstractItemView {
                border: 1px solid #d0d7de;
                background-color: white;
                selection-background-color: #0969da;
                selection-color: white;
                padding: 4px;
            }
            QComboBox QAbstractItemView::item {
                min-height: 24px;
                padding: 4px 8px;
            }
            QComboBox QAbstractItemView::item:hover {
                background-color: #f3f4f6;
            }
        """)
        self.partition_combo.currentIndexChanged.connect(self.on_partition_changed)
        self.toolbar.addWidget(self.partition_combo)
        
        # Export Selected button
        self.toolbar.addSeparator()
        self.export_action = QAction(
            QIcon.fromTheme("document-save", QApplication.style().standardIcon(QStyle.SP_DialogSaveButton)), 
            "Export Selected", self
        )
        self.export_action.setEnabled(False)
        self.export_action.triggered.connect(self.export_selected)
        self.toolbar.addAction(self.export_action)
        
        # Export Full Recycle Bin button
        self.export_all_action = QAction(
            QIcon.fromTheme("document-save-all", QApplication.style().standardIcon(QStyle.SP_DialogSaveButton)), 
            "Export All", self
        )
        self.export_all_action.setToolTip("Export all recoverable files from the Recycle Bin")
        self.export_all_action.setEnabled(False)
        self.export_all_action.triggered.connect(self.export_full_recycle_bin)
        self.toolbar.addAction(self.export_all_action)
        
        # Generate Report button
        self.report_action = QAction(
            QIcon.fromTheme("x-office-spreadsheet", QApplication.style().standardIcon(QStyle.SP_FileDialogDetailedView)), 
            "Generate Report", self
        )
        self.report_action.setEnabled(False)
        self.report_action.triggered.connect(self.generate_report)
        self.toolbar.addAction(self.report_action)
        
        # Statistics button
        self.stats_action = QAction(
            QIcon.fromTheme("view-statistics", QApplication.style().standardIcon(QStyle.SP_ComputerIcon)), 
            "Statistics", self
        )
        self.stats_action.setEnabled(False)
        self.stats_action.triggered.connect(self.show_statistics)
        self.toolbar.addAction(self.stats_action)
        
        # View toggle
        self.toolbar.addSeparator()
        self.view_action = QAction(
            QIcon.fromTheme("view-list-icons", QApplication.style().standardIcon(QStyle.SP_FileDialogListView)), 
            "List View", self
        )
        self.view_action.triggered.connect(self.toggle_view)
        self.toolbar.addAction(self.view_action)
        
        # Add spacer to push search/filter to right
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.toolbar.addWidget(spacer)
        
        # Search box
        self.search_label = QLabel("Search:")
        self.search_label.setStyleSheet("font-weight: 600; color: #475569; background: transparent;")
        self.toolbar.addWidget(self.search_label)
        
        self.search_box = QLineEdit()
        self.search_box.setFixedWidth(150)
        self.search_box.setPlaceholderText("Search...")
        self.search_box.textChanged.connect(self.on_search_changed)
        self.toolbar.addWidget(self.search_box)
        
        # Filter dropdown
        self.filter_label = QLabel("Filter:")
        self.filter_label.setStyleSheet("font-weight: 600; color: #475569; background: transparent;")
        self.toolbar.addWidget(self.filter_label)
        
        self.filter_combo = QComboBox()
        self.filter_combo.setFixedWidth(120)
        self.filter_combo.addItems(["All", "Not Present", "Image", "Document", "Video", "Audio", "Archive", "Executable", "Other", "Folder"])
        self.filter_combo.setStyleSheet("""
            QComboBox {
                border: 1px solid #d0d7de;
                border-radius: 4px;
                padding: 4px 24px 4px 8px;
                background-color: #f6f8fa;
                color: #24292f;
                font-size: 11px;
            }
            QComboBox:hover {
                background-color: #f3f4f6;
                border-color: #0969da;
            }
            QComboBox QAbstractItemView {
                background-color: #ffffff;
                border: 1px solid #d0d7de;
                padding: 4px;
                selection-background-color: #0969da;
                selection-color: #ffffff;
            }
        """)
        self.filter_combo.currentTextChanged.connect(self.on_filter_changed)
        self.toolbar.addWidget(self.filter_combo)
        
    
    def create_menu_bar(self):
        menu_bar = self.menuBar()

        file_menu = menu_bar.addMenu("File")
        file_menu.addAction(self.open_action)

        self.close_image_action = QAction("Close Image", self)
        self.close_image_action.setShortcut(QKeySequence.Close)
        self.close_image_action.setEnabled(False)
        self.close_image_action.triggered.connect(self.close_image)
        file_menu.addAction(self.close_image_action)

        file_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.setShortcut(QKeySequence.Quit)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        view_menu = menu_bar.addMenu("View")

        self.view_mode_group = QActionGroup(self)
        self.view_mode_group.setExclusive(True)

        self.list_view_action = QAction("List View", self)
        self.list_view_action.setCheckable(True)
        self.list_view_action.setShortcut(QKeySequence("Ctrl+1"))
        self.list_view_action.triggered.connect(lambda: self.set_view_mode("list"))
        self.view_mode_group.addAction(self.list_view_action)
        view_menu.addAction(self.list_view_action)

        self.tile_view_action = QAction("Grid View", self)
        self.tile_view_action.setCheckable(True)
        self.tile_view_action.setShortcut(QKeySequence("Ctrl+2"))
        self.tile_view_action.triggered.connect(lambda: self.set_view_mode("tiles"))
        self.view_mode_group.addAction(self.tile_view_action)
        view_menu.addAction(self.tile_view_action)

        view_menu.addSeparator()

        self.dark_mode_action = QAction("Dark Mode", self)
        self.dark_mode_action.setCheckable(True)
        self.dark_mode_action.setShortcut(QKeySequence("Ctrl+D"))
        self.dark_mode_action.toggled.connect(self.set_dark_mode)
        view_menu.addAction(self.dark_mode_action)

        tools_menu = menu_bar.addMenu("Tools")
        tools_menu.addAction(self.export_action)
        tools_menu.addAction(self.export_all_action)
        tools_menu.addSeparator()
        tools_menu.addAction(self.report_action)
        tools_menu.addAction(self.stats_action)

        help_menu = menu_bar.addMenu("Help")
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def show_about(self):
        """Show compact about dialog."""
        dialog = QDialog(self)
        dialog.setWindowTitle("About")
        dialog.setFixedSize(480, 380)
        dialog.setStyleSheet("""
            QDialog {
                background-color: #ffffff;
            }
            QLabel {
                background: transparent;
            }
            QPushButton {
                background-color: #0969da;
                color: white;
                border: none;
                padding: 8px 24px;
                border-radius: 6px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #0860c7;
            }
        """)
        
        layout = QHBoxLayout(dialog)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)
        
        # Icon on left - smaller
        icon_label = QLabel()
        icon_label.setPixmap(QApplication.style().standardIcon(QStyle.SP_MessageBoxInformation).pixmap(48, 48))
        icon_label.setAlignment(Qt.AlignTop)
        layout.addWidget(icon_label)
        
        # Content on right
        content_layout = QVBoxLayout()
        content_layout.setSpacing(8)
        
        # Title
        title = QLabel("<b style='font-size:16px; color:#24292f;'>Recycle Bin Forensic Explorer v1.0</b>")
        title.setTextFormat(Qt.RichText)
        content_layout.addWidget(title)
        
        # Subtitle
        subtitle = QLabel("<span style='color:#57606a;'>Forensic analysis tool for Windows Recycle Bin from E01 images.</span>")
        subtitle.setTextFormat(Qt.RichText)
        subtitle.setWordWrap(True)
        content_layout.addWidget(subtitle)
        
        content_layout.addSpacing(5)
        
        # Features - compact
        features_html = """<div style='font-size:12px; color:#24292f;'>
<b>Features:</b><br>
• <b style='color:#0969da;'>E01 Image Support</b> - Open Expert Witness Format forensic images<br>
• <b style='color:#0969da;'>Partition Detection</b> - Auto-detect partitions within images<br>
• <b style='color:#0969da;'>Recycle Bin Analysis</b> - Parse $I/$R files for deleted file metadata<br>
• <b style='color:#0969da;'>File Recovery</b> - Export files with timestamps preserved<br>
• <b style='color:#0969da;'>Hash Calculation</b> - MD5, SHA-1, SHA-256 during export<br>
• <b style='color:#0969da;'>Reports</b> - CSV/JSON with export statistics<br>
• <b style='color:#0969da;'>Dark/Light Mode</b> - Theme toggle (Ctrl+D)
</div>"""
        features = QLabel(features_html)
        features.setTextFormat(Qt.RichText)
        features.setWordWrap(True)
        content_layout.addWidget(features)
        
        content_layout.addSpacing(5)
        
        # Usage & Shortcuts compact
        usage_html = """<div style='font-size:11px; color:#57606a;'>
<b>Usage:</b> Open Image → Select Partition → Browse/Select Files → Export<br>
<b>Shortcuts:</b> <b>Ctrl+O</b> Open | <b>Ctrl+1</b> List | <b>Ctrl+2</b> Grid | <b>Ctrl+D</b> Dark Mode
</div>"""
        usage = QLabel(usage_html)
        usage.setTextFormat(Qt.RichText)
        usage.setWordWrap(True)
        content_layout.addWidget(usage)
        
        content_layout.addStretch()
        
        # Footer
        footer = QLabel("<span style='color:#8c959f; font-size:10px;'>Built with PySide6, pyewf, pytsk3</span>")
        footer.setTextFormat(Qt.RichText)
        content_layout.addWidget(footer)
        
        # OK button
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        ok_btn = QPushButton("OK")
        ok_btn.clicked.connect(dialog.accept)
        ok_btn.setFixedWidth(80)
        btn_layout.addWidget(ok_btn)
        content_layout.addLayout(btn_layout)
        
        layout.addLayout(content_layout)
        dialog.exec()
    
    def create_left_panel(self):
        """Create the left panel with directory tree."""
        # Create left widget with modern styling
        self.left_widget = QWidget()
        self.left_widget.setStyleSheet("""
            QWidget {
                background-color: #ffffff;
                border-right: 1px solid #c0c0c0;
            }
        """)
        left_layout = QVBoxLayout(self.left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(0)
        
        # Add header - FTK Imager style "Evidence Tree" header
        self.tree_header_widget = QWidget()
        self.tree_header_widget.setStyleSheet("""
            QWidget {
                background-color: #0078d4;
                border: none;
            }
        """)
        header_layout = QHBoxLayout(self.tree_header_widget)
        header_layout.setContentsMargins(8, 6, 8, 6)
        header_layout.setSpacing(8)
        
        header_label = QLabel("Evidence Tree")
        header_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        header_label.setStyleSheet("color: white; background: transparent; border: none;")
        header_layout.addWidget(header_label)
        header_layout.addStretch()
        left_layout.addWidget(self.tree_header_widget)
        
        # Create tree view - FTK Imager style
        self.tree_view = QTreeView()
        self.tree_view.setHeaderHidden(False)
        self.tree_view.setSelectionMode(QTreeView.SingleSelection)
        self.tree_view.setEditTriggers(QTreeView.NoEditTriggers)
        self.tree_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree_view.customContextMenuRequested.connect(self.show_tree_context_menu)
        self.tree_view.clicked.connect(self.on_tree_item_clicked)
        self.tree_view.setAnimated(True)
        self.tree_view.setIndentation(12)
        self.tree_view.setRootIsDecorated(True)
        self.tree_view.setItemsExpandable(True)
        self.tree_view.setExpandsOnDoubleClick(True)
        self.tree_view.setAlternatingRowColors(True)
        self.tree_view.setStyleSheet("""
            QTreeView {
                border: none;
                background-color: #ffffff;
                selection-background-color: #0078d4;
                selection-color: white;
                font-size: 11px;
                font-family: "Segoe UI", Arial, sans-serif;
                outline: none;
            }
            QTreeView::item {
                padding: 2px 4px;
                min-height: 20px;
            }
            QTreeView::item:hover {
                background-color: #e5f3ff;
            }
            QTreeView::item:selected {
                background-color: #0078d4;
                color: white;
            }
            QTreeView::item:selected:!active {
                background-color: #cce8ff;
                color: black;
            }
            QHeaderView::section {
                background-color: #f0f0f0;
                color: #333333;
                font-weight: bold;
                font-size: 11px;
                padding: 4px 8px;
                border: none;
                border-right: 1px solid #c0c0c0;
                border-bottom: 1px solid #c0c0c0;
            }
        """)
        
        # Create tree model
        self.tree_model = FileSystemModel()
        self.tree_view.setModel(self.tree_model)
        left_layout.addWidget(self.tree_view)
        
        # Add to splitter
        self.splitter.addWidget(self.left_widget)
    
    def create_right_panel(self):
        """Create the right panel with file view."""
        # Create right widget
        self.right_widget = QWidget()
        self.right_widget.setStyleSheet("background-color: #ffffff;")
        right_layout = QVBoxLayout(self.right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)
        
        # Add header - FTK Imager style "File List" header
        self.file_list_header = QWidget()
        self.file_list_header.setStyleSheet("""
            QWidget {
                background-color: #0078d4;
                border: none;
            }
        """)
        file_list_header_layout = QHBoxLayout(self.file_list_header)
        file_list_header_layout.setContentsMargins(8, 6, 8, 6)
        file_list_header_layout.setSpacing(8)
        
        file_list_label = QLabel("File List")
        file_list_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        file_list_label.setStyleSheet("color: white; background: transparent; border: none;")
        file_list_header_layout.addWidget(file_list_label)
        file_list_header_layout.addStretch()
        right_layout.addWidget(self.file_list_header)
        
        # Content area with padding
        self.content_widget = QWidget()
        self.content_widget.setStyleSheet("background-color: #f5f7fa;")
        content_layout = QVBoxLayout(self.content_widget)
        content_layout.setContentsMargins(16, 16, 16, 16)
        content_layout.setSpacing(12)
        
        # Create breadcrumb navigation
        self.create_breadcrumb_navigation(content_layout)
        
        # Create header with title and controls
        header_widget = QWidget()
        header_widget.setStyleSheet("background: transparent;")
        header_layout = QHBoxLayout(header_widget)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(8)
        
        # Title label
        self.title_label = QLabel("All Deleted Files")
        self.title_label.setFont(QFont("Segoe UI", 14, QFont.Bold))
        self.title_label.setStyleSheet("color: #1e293b; background: transparent;")
        header_layout.addWidget(self.title_label)
        
        # Add spacer
        header_layout.addStretch()
        
        # Sort options
        sort_label = QLabel("Sort:")
        sort_label.setStyleSheet("font-weight: 600; color: #64748b; background: transparent;")
        header_layout.addWidget(sort_label)
        
        self.sort_combo = QComboBox()
        self.sort_combo.setMinimumWidth(140)
        self.sort_combo.addItems([
            "Date (newest)", "Date (oldest)",
            "Size (largest)", "Size (smallest)",
            "Name (A-Z)", "Name (Z-A)"
        ])
        self.sort_combo.setStyleSheet("""
            QComboBox {
                border: 1px solid #d0d7de;
                border-radius: 6px;
                padding: 5px 30px 5px 10px;
                background-color: #f6f8fa;
                color: #24292f;
                font-size: 12px;
                min-height: 24px;
            }
            QComboBox:hover {
                background-color: #f3f4f6;
                border-color: #0969da;
            }
            QComboBox QAbstractItemView {
                background-color: white;
                selection-background-color: #0969da;
                selection-color: white;
                border: 1px solid #d0d7de;
                padding: 4px;
                outline: none;
            }
        """)
        self.sort_combo.currentTextChanged.connect(self.on_sort_changed)
        header_layout.addWidget(self.sort_combo)
        
        # Selection controls with modern styling
        self.select_all_btn = QPushButton("✓ Select All")
        self.select_all_btn.clicked.connect(self.select_all)
        self.select_all_btn.setStyleSheet("""
            QPushButton {
                background-color: #10b981;
                color: white;
                border: none;
                padding: 10px 18px;
                border-radius: 6px;
                font-weight: 600;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #059669;
            }
            QPushButton:pressed {
                background-color: #047857;
            }
        """)
        header_layout.addWidget(self.select_all_btn)
        
        self.deselect_all_btn = QPushButton("✕ Clear")
        self.deselect_all_btn.clicked.connect(self.deselect_all)
        self.deselect_all_btn.setStyleSheet("""
            QPushButton {
                background-color: #ef4444;
                color: white;
                border: none;
                padding: 10px 18px;
                border-radius: 6px;
                font-weight: 600;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #dc2626;
            }
            QPushButton:pressed {
                background-color: #b91c1c;
            }
        """)
        header_layout.addWidget(self.deselect_all_btn)
        
        # Selection count button - shows count and opens selection manager
        self.selection_count_btn = QPushButton("📋 0 Selected")
        self.selection_count_btn.clicked.connect(self.show_selection_manager)
        self.selection_count_btn.setStyleSheet("""
            QPushButton {
                background-color: #3b82f6;
                color: white;
                border: none;
                padding: 10px 18px;
                border-radius: 6px;
                font-weight: 600;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #2563eb;
            }
            QPushButton:pressed {
                background-color: #1d4ed8;
            }
        """)
        header_layout.addWidget(self.selection_count_btn)
        
        content_layout.addWidget(header_widget)
        
        # Date range filter row
        date_filter_widget = QWidget()
        date_filter_widget.setStyleSheet("background: transparent;")
        date_filter_layout = QHBoxLayout(date_filter_widget)
        date_filter_layout.setContentsMargins(0, 0, 0, 8)
        date_filter_layout.setSpacing(8)
        
        date_filter_label = QLabel("Deletion Date:")
        date_filter_label.setStyleSheet("font-weight: 600; color: #64748b; background: transparent;")
        date_filter_layout.addWidget(date_filter_label)
        
        from_label = QLabel("From:")
        from_label.setStyleSheet("color: #64748b; background: transparent;")
        date_filter_layout.addWidget(from_label)
        
        from PySide6.QtCore import QDate
        
        # Use custom DatePickerWidget with calendar icon button
        self.date_from = DatePickerWidget(initial_date=QDate(2000, 1, 1))
        self.date_from.dateChanged.connect(self.on_date_filter_changed)
        date_filter_layout.addWidget(self.date_from)
        
        to_label = QLabel("To:")
        to_label.setStyleSheet("color: #64748b; background: transparent;")
        date_filter_layout.addWidget(to_label)
        
        self.date_to = DatePickerWidget(initial_date=QDate.currentDate())
        self.date_to.dateChanged.connect(self.on_date_filter_changed)
        date_filter_layout.addWidget(self.date_to)
        
        self.clear_date_filter_btn = QPushButton("Clear Dates")
        self.clear_date_filter_btn.setStyleSheet("""
            QPushButton {
                background-color: #64748b;
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 4px;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #475569;
            }
        """)
        self.clear_date_filter_btn.clicked.connect(self.clear_date_filter)
        date_filter_layout.addWidget(self.clear_date_filter_btn)
        
        # Timezone selector (in date filter row for better visibility)
        date_filter_layout.addSpacing(20)
        tz_label = QLabel("Timezone:")
        tz_label.setStyleSheet("font-weight: 600; color: #64748b; background: transparent;")
        date_filter_layout.addWidget(tz_label)
        
        self.tz_combo = QComboBox()
        self.tz_combo.setMinimumWidth(130)
        self.tz_combo.addItems(self.available_timezones)
        self.tz_combo.setCurrentText(self.current_timezone)
        self.tz_combo.currentTextChanged.connect(self.on_timezone_changed)
        self.tz_combo.setStyleSheet("""
            QComboBox {
                border: 1px solid #d0d7de;
                border-radius: 6px;
                padding: 5px 28px 5px 10px;
                background-color: #f6f8fa;
                color: #24292f;
                min-width: 120px;
                font-size: 12px;
            }
            QComboBox:hover {
                background-color: #f3f4f6;
                border-color: #afb8c1;
            }
            QComboBox QAbstractItemView {
                background-color: #ffffff;
                selection-background-color: #0969da;
                selection-color: #ffffff;
                border: 1px solid #d0d7de;
                padding: 4px;
            }
        """)
        date_filter_layout.addWidget(self.tz_combo)
        
        date_filter_layout.addStretch()
        content_layout.addWidget(date_filter_widget)
        
        # Create stacked widget for different views
        self.view_stack = QWidget()
        self.view_stack.setStyleSheet("background: transparent;")
        view_layout = QVBoxLayout(self.view_stack)
        view_layout.setContentsMargins(0, 0, 0, 0)
        
        # Create tile view (grid layout in scroll area)
        self.tile_scroll = QScrollArea()
        self.tile_scroll.setWidgetResizable(True)
        self.tile_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.tile_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.tile_scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: #f6f8fa;
            }
            QScrollArea > QWidget > QWidget {
                background-color: #f6f8fa;
            }
        """)
        
        # Use ResponsiveGridWidget for Windows Explorer-like tile layout
        self.tile_widget = ResponsiveGridWidget()
        self.tile_widget.setStyleSheet("background-color: #f6f8fa;")
        self.tile_scroll.setWidget(self.tile_widget)
        
        view_layout.addWidget(self.tile_scroll)
        
        # Create list view
        self.list_view = QListView()
        self.list_view.setSelectionMode(QListView.ExtendedSelection)
        self.list_view.setUniformItemSizes(True)
        self.list_view.setResizeMode(QListView.Adjust)  # Repaint items on resize
        self.list_view.setSpacing(4)
        self.list_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.list_view.customContextMenuRequested.connect(self.show_list_context_menu)
        self.list_view.doubleClicked.connect(self.on_item_double_clicked)
        self.list_view.setStyleSheet("""
            QListView {
                border: 1px solid #e2e8f0;
                border-radius: 12px;
                background-color: #ffffff;
                selection-background-color: #4f46e5;
                selection-color: white;
                padding: 8px;
            }
            QListView::item {
                border-radius: 6px;
                padding: 8px;
                margin: 2px 4px;
            }
            QListView::item:hover {
                background-color: #f1f5f9;
            }
            QListView::item:selected {
                background-color: #4f46e5;
                color: white;
            }
        """)
        
        # Create list model
        self.list_model = QStandardItemModel()
        self.list_view.setModel(self.list_model)
        
        # Connect selection model signal
        self.list_view.selectionModel().selectionChanged.connect(self.on_list_selection_changed)
        
        # Create item delegate with timezone formatter
        self.item_delegate = FileItemDelegate(datetime_formatter=self.format_datetime_tz)
        self.list_view.setItemDelegate(self.item_delegate)
        
        view_layout.addWidget(self.list_view)
        self.list_view.setVisible(False)  # Hide initially
        
        content_layout.addWidget(self.view_stack)
        
        # Add content widget to right layout
        right_layout.addWidget(self.content_widget)
        
        # Add to splitter
        self.splitter.addWidget(self.right_widget)
    
    def create_breadcrumb_navigation(self, layout):
        """Create breadcrumb navigation for folder browsing."""
        self.breadcrumb_widget = QWidget()
        self.breadcrumb_widget.setVisible(False)
        self.breadcrumb_widget.setStyleSheet("""
            QWidget {
                background-color: #f1f5f9;
                border-radius: 8px;
                padding: 4px;
            }
        """)
        breadcrumb_layout = QHBoxLayout(self.breadcrumb_widget)
        breadcrumb_layout.setContentsMargins(8, 8, 8, 8)
        breadcrumb_layout.setSpacing(12)
        
        # Back button
        self.back_button = QPushButton("← Back")
        self.back_button.clicked.connect(self.navigate_back)
        self.back_button.setStyleSheet("""
            QPushButton {
                background-color: #64748b;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                font-size: 12px;
                font-weight: 500;
            }
            QPushButton:hover {
                background-color: #475569;
            }
            QPushButton:pressed {
                background-color: #334155;
            }
        """)
        breadcrumb_layout.addWidget(self.back_button)
        
        # Breadcrumb path
        self.breadcrumb_label = ElidedLabel()
        self.breadcrumb_label.setStyleSheet("color: #475569; font-size: 13px; font-weight: 500; background: transparent;")
        self.breadcrumb_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        breadcrumb_layout.addWidget(self.breadcrumb_label)
        
        breadcrumb_layout.addStretch()
        layout.addWidget(self.breadcrumb_widget)
    
    def apply_modern_theme(self):
        """Apply a modern flat design theme to the application."""
        # Create a modern palette
        palette = QPalette()
        
        # Base colors - Modern flat design
        palette.setColor(QPalette.Window, QColor(245, 247, 250))  # Soft gray background
        palette.setColor(QPalette.WindowText, QColor(30, 41, 59))  # Slate dark text
        palette.setColor(QPalette.Base, QColor(255, 255, 255))  # White input backgrounds
        palette.setColor(QPalette.AlternateBase, QColor(241, 245, 249))  # Alternate row color
        palette.setColor(QPalette.ToolTipBase, QColor(50, 50, 50))  # Dark gray tooltip bg
        palette.setColor(QPalette.ToolTipText, QColor(255, 255, 255))  # White tooltip text
        palette.setColor(QPalette.Text, QColor(30, 41, 59))  # Slate dark text
        palette.setColor(QPalette.Button, QColor(241, 245, 249))
        palette.setColor(QPalette.ButtonText, QColor(30, 41, 59))
        
        # Modern indigo highlight
        palette.setColor(QPalette.Highlight, QColor(79, 70, 229))  # Indigo primary
        palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
        
        # Links
        palette.setColor(QPalette.Link, QColor(79, 70, 229))
        palette.setColor(QPalette.LinkVisited, QColor(109, 40, 217))
        
        # Apply palette
        QApplication.setPalette(palette)
        
        # Apply comprehensive global stylesheet for modern professional look
        self.setStyleSheet("""
            /* Tooltip - dark background for visibility on light theme */
            QToolTip {
                background-color: #24292f;
                color: #ffffff;
                border: 1px solid #24292f;
                border-radius: 6px;
                padding: 8px;
                font-size: 11px;
            }
            QToolTip QLabel {
                color: #ffffff;
            }

            /* Main Window */
            QMainWindow {
                background-color: #f5f7fa;
            }
            
            /* Toolbar Styling */
            QToolBar {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                          stop: 0 #ffffff, stop: 1 #f8fafc);
                border: none;
                border-bottom: 1px solid #e2e8f0;
                padding: 8px 12px;
                spacing: 4px;
            }
            QToolBar QToolButton {
                background-color: transparent;
                border: none;
                border-radius: 8px;
                padding: 8px 10px;
                margin: 0px 2px;
                color: #475569;
                font-weight: 500;
                min-height: 50px;
            }
            QToolBar QToolButton:hover {
                background-color: #f1f5f9;
                color: #1e293b;
            }
            QToolBar QToolButton:pressed {
                background-color: #e2e8f0;
            }
            QToolBar QToolButton:disabled {
                color: #94a3b8;
            }
            
            /* ComboBox Styling - Fixed dropdown visibility */
            QComboBox {
                border: 1px solid #cbd5e1;
                border-radius: 6px;
                padding: 8px 12px;
                padding-right: 30px;
                background-color: #ffffff;
                color: #1e293b;
                font-size: 13px;
                min-height: 20px;
                selection-background-color: #4f46e5;
                selection-color: #ffffff;
            }
            QComboBox:hover {
                border-color: #94a3b8;
                background-color: #f8fafc;
            }
            QComboBox:focus {
                border-color: #4f46e5;
                outline: none;
            }
            QComboBox:disabled {
                background-color: #f1f5f9;
                color: #94a3b8;
                border-color: #e2e8f0;
            }
            QComboBox QAbstractItemView {
                background-color: #ffffff;
                border: 1px solid #cbd5e1;
                border-radius: 6px;
                padding: 4px;
                selection-background-color: #4f46e5;
                selection-color: #ffffff;
                outline: none;
            }
            QComboBox QAbstractItemView::item {
                padding: 8px 12px;
                min-height: 28px;
                color: #1e293b;
                background-color: #ffffff;
                border-radius: 4px;
                margin: 2px;
            }
            QComboBox QAbstractItemView::item:hover {
                background-color: #f1f5f9;
                color: #1e293b;
            }
            QComboBox QAbstractItemView::item:selected {
                background-color: #4f46e5;
                color: #ffffff;
            }
            
            /* Date Edit Styling - now using custom DatePickerWidget with calendar button */
            QDateEdit {
                border: 1px solid #cbd5e1;
                border-radius: 6px;
                padding: 6px 12px;
                padding-right: 30px;
                background-color: #ffffff;
                color: #1e293b;
                font-size: 13px;
                min-height: 20px;
            }
            QDateEdit:hover {
                border-color: #94a3b8;
                background-color: #f8fafc;
            }
            QDateEdit:focus {
                border-color: #4f46e5;
                outline: none;
            }
            QDateEdit::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: center right;
                width: 26px;
                border-left: 1px solid #e2e8f0;
                border-top-right-radius: 6px;
                border-bottom-right-radius: 6px;
                background-color: #e2e8f0;
            }
            
            /* LineEdit Styling */
            QLineEdit {
                border: 1px solid #cbd5e1;
                border-radius: 6px;
                padding: 8px 12px;
                background-color: #ffffff;
                color: #1e293b;
                font-size: 13px;
                selection-background-color: #4f46e5;
                selection-color: #ffffff;
            }
            QLineEdit:hover {
                border-color: #94a3b8;
            }
            QLineEdit:focus {
                border-color: #4f46e5;
                outline: none;
            }
            QLineEdit::placeholder {
                color: #94a3b8;
            }
            
            /* Label Styling */
            QLabel {
                color: #475569;
                font-size: 13px;
            }
            
            /* Status Bar */
            QStatusBar {
                background-color: #ffffff;
                border-top: 1px solid #e2e8f0;
                color: #64748b;
                padding: 4px 12px;
                font-size: 12px;
            }
            QStatusBar::item {
                border: none;
            }
            
            /* Progress Bar */
            QProgressBar {
                border: none;
                border-radius: 4px;
                background-color: #e2e8f0;
                text-align: center;
                color: #475569;
                font-size: 11px;
                font-weight: 500;
                min-height: 8px;
                max-height: 8px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
                                          stop: 0 #4f46e5, stop: 1 #7c3aed);
                border-radius: 4px;
            }
            
            /* Splitter */
            QSplitter::handle {
                background-color: #e2e8f0;
                width: 2px;
            }
            QSplitter::handle:hover {
                background-color: #4f46e5;
            }
            
            /* Scroll Bars - GitHub style */
            QScrollBar:vertical {
                background: #f6f8fa;
                width: 12px;
            }
            QScrollBar::handle:vertical {
                background: #d0d7de;
                border-radius: 6px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background: #afb8c1;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0;
                background: none;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: none;
            }
            QScrollBar:horizontal {
                background: #f6f8fa;
                height: 12px;
            }
            QScrollBar::handle:horizontal {
                background: #d0d7de;
                border-radius: 6px;
                min-width: 20px;
            }
            QScrollBar::handle:horizontal:hover {
                background: #afb8c1;
            }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                width: 0;
                background: none;
            }
            
            /* Message Box */
            QMessageBox {
                background-color: #ffffff;
            }
            QMessageBox QLabel {
                color: #1e293b;
                font-size: 13px;
            }
            QMessageBox QPushButton {
                background-color: #4f46e5;
                color: #ffffff;
                border: none;
                border-radius: 6px;
                padding: 8px 20px;
                font-weight: 500;
                min-width: 80px;
            }
            QMessageBox QPushButton:hover {
                background-color: #4338ca;
            }
            
            /* Group Box */
            QGroupBox {
                font-weight: 600;
                color: #1e293b;
                border: 1px solid #e2e8f0;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 12px;
                background-color: #ffffff;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                left: 12px;
                padding: 0 8px;
                background-color: #ffffff;
            }
            
            /* Check Box - GitHub style */
            QCheckBox {
                color: #24292f;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 14px;
                height: 14px;
                border-radius: 3px;
                border: 1.5px solid #d0d7de;
                background: #fff;
            }
            QCheckBox::indicator:hover {
                border-color: #0969da;
            }
            QCheckBox::indicator:checked {
                background: #0969da;
                border-color: #0969da;
            }
            
            /* Radio Button */
            QRadioButton {
                color: #1e293b;
                spacing: 8px;
            }
            QRadioButton::indicator {
                width: 18px;
                height: 18px;
                border: 2px solid #cbd5e1;
                border-radius: 9px;
                background-color: #ffffff;
            }
            QRadioButton::indicator:hover {
                border-color: #4f46e5;
            }
            QRadioButton::indicator:checked {
                background-color: #4f46e5;
                border-color: #4f46e5;
            }
            
            /* Tab Widget */
            QTabWidget::pane {
                border: 1px solid #e2e8f0;
                border-radius: 8px;
                background-color: #ffffff;
                top: -1px;
            }
            QTabBar::tab {
                background-color: #f1f5f9;
                color: #64748b;
                border: 1px solid #e2e8f0;
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                padding: 10px 20px;
                margin-right: 2px;
                font-weight: 500;
            }
            QTabBar::tab:selected {
                background-color: #ffffff;
                color: #4f46e5;
                border-bottom: 2px solid #4f46e5;
            }
            QTabBar::tab:hover:!selected {
                background-color: #e2e8f0;
                color: #1e293b;
            }
            
            /* Menu */
            QMenu {
                background-color: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 8px;
                padding: 6px;
            }
            QMenu::item {
                padding: 8px 24px 8px 12px;
                border-radius: 4px;
                color: #1e293b;
            }
            QMenu::item:selected {
                background-color: #f1f5f9;
            }
            QMenu::separator {
                height: 1px;
                background-color: #e2e8f0;
                margin: 4px 8px;
            }
        """)
    
    def open_image(self):
        """Open an E01 image file."""
        # Show file dialog
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Forensic Image",
            "",
            "E01 Images (*.e01);;Raw Images (*.dd *.raw *.img);;All Files (*.*)"
        )
        
        if not file_path:
            return
        
        # Log image file being loaded
        logger.info("="*60)
        logger.info("LOADING IMAGE FILE")
        logger.info("="*60)
        logger.info(f"Image path: {file_path}")
        logger.info(f"File size: {os.path.getsize(file_path) / (1024**3):.2f} GB")
        logger.info(f"Load started at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Clear previous state when loading new image
        self.clear_current_view()
        self.partition_cache.clear()
        self.current_partition = None
        self.is_processing_partition = False
        
        # Block signals while clearing combo to prevent triggering on_partition_changed
        self.partition_combo.blockSignals(True)
        self.partition_combo.clear()
        self.partition_combo.blockSignals(False)
        self.partition_combo.setEnabled(False)
        
        # Update status
        self.statusBar.showMessage(f"Opening image: {os.path.basename(file_path)}...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        # Create parser
        self.parser = RecycleBinParser(file_path, debug=True)
        self.image_path = file_path
        
        # Create worker threads
        self.hash_worker = HashWorker(self.parser)
        self.hash_worker.hash_ready.connect(self.on_hash_ready)
        
        self.export_worker = ExportWorker(self.parser)
        self.export_worker.progress_update.connect(self.on_export_progress)
        self.export_worker.export_complete.connect(self.on_export_complete)
        
        # Run in a separate thread
        self.load_image_thread = LoadImageThread(self.parser)
        self.load_image_thread.progress_update.connect(self.on_load_progress)
        self.load_image_thread.partitions_ready.connect(self.on_partitions_ready)
        self.load_image_thread.start()
    
    def on_load_progress(self, progress, message):
        """Handle progress updates from the load thread."""
        self.progress_bar.setValue(progress)
        self.statusBar.showMessage(message)
    
    def on_partitions_ready(self, partitions):
        """Handle partitions detected in the image."""
        # Update UI
        self.progress_bar.setVisible(False)
        
        if not partitions:
            QMessageBox.warning(self, "No Partitions", "No partitions were detected in the image.")
            return
        
        # Block signals while populating to prevent triggering on_partition_changed
        self.partition_combo.blockSignals(True)
        self.partition_combo.clear()
        for i, part in enumerate(partitions):
            size_gb = part['size'] / (1024**3)
            self.partition_combo.addItem(f"{i}: {part['desc']} ({size_gb:.2f} GB)", i)
        self.partition_combo.blockSignals(False)
        
        # Enable partition selection
        self.partition_combo.setEnabled(True)
        
        # Log partition info
        logger.info(f"Image loaded successfully with {len(partitions)} partition(s)")
        for i, part in enumerate(partitions):
            logger.info(f"  Partition {i}: {part['desc']} ({part['size'] / (1024**3):.2f} GB)")
        
        # Select first partition automatically or show popup to select
        if len(partitions) == 1:
            self.partition_combo.setCurrentIndex(0)
            QMessageBox.information(
                self, "Image Loaded", 
                f"Image loaded successfully!\n\n"
                f"Found 1 partition: {partitions[0]['desc']}\n"
                f"Size: {partitions[0]['size'] / (1024**3):.2f} GB\n\n"
                f"Processing partition automatically..."
            )
        else:
            self.statusBar.showMessage("Select a partition to analyze.")
            # Show popup to inform user to select partition
            QMessageBox.information(
                self, "Image Loaded - Select Partition", 
                f"Image loaded successfully!\n\n"
                f"Found {len(partitions)} partitions.\n\n"
                f"Please select a partition from the dropdown\n"
                f"in the toolbar to begin analysis."
            )
    
    def on_partition_changed(self, index):
        """Handle partition selection change."""
        if index < 0 or not self.parser:
            return
        
        # Prevent processing if already processing
        if self.is_processing_partition:
            return
        
        partition_index = self.partition_combo.itemData(index)
        
        # Skip if same partition
        if partition_index == self.current_partition:
            return
        
        self.current_partition = partition_index
        
        # Clear current state before loading new partition
        self.clear_current_view()
        
        # Check if partition is already cached
        if partition_index in self.partition_cache:
            cached_artifacts = self.partition_cache[partition_index]
            self.statusBar.showMessage(f"Loading cached data for partition {partition_index}...")
            # Use cached data directly
            self.on_artifacts_ready(cached_artifacts, from_cache=True)
            return
        
        # Update status
        self.statusBar.showMessage(f"Processing partition {partition_index}...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.is_processing_partition = True
        
        # Process partition in a separate thread
        self.process_partition_thread = ProcessPartitionThread(self.parser, partition_index)
        self.process_partition_thread.progress_update.connect(self.on_load_progress)
        self.process_partition_thread.artifacts_ready.connect(self.on_artifacts_ready)
        self.process_partition_thread.start()
    
    def clear_current_view(self):
        """Clear the current view and reset state for partition switch."""
        # Clear artifacts
        self.artifacts = []
        self.selected_artifacts = []
        self.current_displayed_artifacts = []
        self.current_tree_context = "root"
        self.current_folder = None
        self.current_page = 0
        self.folder_navigation_stack = []
        
        # Clear tree view
        self.tree_model.clear()
        
        # Clear file view
        if self.current_view_mode == "list":
            self.list_model.clear()
        else:
            # Clear tile view using ResponsiveGridWidget
            self.tile_widget.clear_cards()
        
        # Update title
        self.title_label.setText("No files to display")
        
        # Disable actions until new data is loaded
        self.export_action.setEnabled(False)
        self.export_all_action.setEnabled(False)
        self.report_action.setEnabled(False)
        self.stats_action.setEnabled(False)

        self.current_filtered_count = 0
        self.update_persistent_status()

    def update_persistent_status(self, showing_count=None):
        if showing_count is not None:
            self.current_filtered_count = int(showing_count)

        total = len(self.artifacts) if self.artifacts else 0
        recoverable_total = len([a for a in self.artifacts if a.get('r_file_recovered')]) if self.artifacts else 0
        unrecoverable_total = max(0, total - recoverable_total)

        showing = min(max(0, int(getattr(self, 'current_filtered_count', total))), total) if total else int(getattr(self, 'current_filtered_count', 0))

        dataset_text = f"Show {showing}/{total} | Rec {recoverable_total} | Unrec {unrecoverable_total}"
        self.dataset_status_label.setText(dataset_text)
        self.dataset_status_label.setToolTip(dataset_text)

        selected = len(self.selected_artifacts) if self.selected_artifacts else 0
        selected_recoverable = len([a for a in self.selected_artifacts if a.get('r_file_recovered')]) if self.selected_artifacts else 0
        selection_text = f"Sel {selected} (Rec {selected_recoverable})"
        self.selection_status_label.setText(selection_text)
    
    def on_artifacts_ready(self, artifacts, from_cache=False):
        """Handle artifacts loaded from the partition."""
        # Reset processing flag
        self.is_processing_partition = False
        
        # Update UI
        self.progress_bar.setVisible(False)
        
        if not artifacts:
            # Clear the view and show message for empty partition
            self.clear_current_view()
            self.statusBar.showMessage("No Recycle Bin artifacts found in this partition.")
            # Cache empty result to avoid re-processing
            if self.current_partition is not None:
                self.partition_cache[self.current_partition] = []
            return
        
        # Cache the artifacts if not from cache
        if not from_cache and self.current_partition is not None:
            self.partition_cache[self.current_partition] = artifacts
        
        # Store artifacts (fresh copy to avoid reference issues)
        self.artifacts = list(artifacts)
        self.all_artifacts = list(artifacts)
        self.selected_artifacts = []
        self.current_tree_context = "root"
        self.current_folder = None
        self.folder_navigation_stack = []
        if hasattr(self, 'breadcrumb_widget'):
            self.breadcrumb_widget.setVisible(False)
        
        # Update tree view
        self.tree_model.populate_from_artifacts(artifacts)
        self.tree_view.expandToDepth(0)
        
        # Update file view
        self.apply_current_filters()
        
        # Enable actions (but export selected needs selection)
        self.export_action.setEnabled(False)  # Needs selection first
        self.export_all_action.setEnabled(True)  # Can export all recoverable files
        self.report_action.setEnabled(True)
        self.stats_action.setEnabled(True)
        self.close_image_action.setEnabled(True)  # Enable close image
        
        # Update status
        recoverable = len([a for a in artifacts if a['r_file_recovered']])
        cache_indicator = " (cached)" if from_cache else ""
        self.statusBar.showMessage(
            f"Loaded {len(artifacts)} deleted files ({recoverable} recoverable){cache_indicator}"
        )
    
    def on_hash_ready(self, artifact_id, hash_results):
        """Handle hash calculation completion."""
        # Find artifact and update with hash values
        for artifact in self.artifacts:
            if artifact['i_file_name'] == artifact_id:
                for key, value in hash_results.items():
                    artifact[key] = value
                break
    
    def update_file_view(self, filtered_artifacts=None):
        """Update the file view with artifacts."""
        artifacts_to_display = filtered_artifacts if filtered_artifacts is not None else self.artifacts
        self.current_displayed_artifacts = list(artifacts_to_display) if artifacts_to_display is not None else []
        self.update_persistent_status(len(artifacts_to_display) if artifacts_to_display is not None else 0)
        
        # Check if we have any artifacts to display
        if not artifacts_to_display:
            self.title_label.setText("No files to display")
            
            # Clear the views
            if self.current_view_mode == "list":
                self.list_model.clear()
            else:
                # Clear tile view using ResponsiveGridWidget
                self.tile_widget.clear_cards()
            return
        
        # Update title
        if self.current_folder:
            self.title_label.setText(f"Deleted Files in {os.path.basename(self.current_folder)} ({len(artifacts_to_display)})")
        else:
            recoverable = len([a for a in artifacts_to_display if a['r_file_recovered']])
            self.title_label.setText(f"All Deleted Files ({len(artifacts_to_display)} total, {recoverable} recoverable)")
        
        # Update view based on current mode
        if self.current_view_mode == "list":
            self.update_list_view(artifacts_to_display)
        else:
            self.update_tile_view(artifacts_to_display)
    
    def update_list_view(self, artifacts=None):
        """Update the list view with artifacts."""
        artifacts_to_display = artifacts if artifacts is not None else self.artifacts
        
        # Clear model
        self.list_model.clear()
        
        # Add artifacts to model
        for artifact in artifacts_to_display:
            item = QStandardItem()
            item.setData(artifact, Qt.UserRole)
            item.setToolTip(artifact.get('original_path', ''))
            item.setEditable(False)  # Prevent editing for forensic integrity
            self.list_model.appendRow(item)
        
        # Show list view
        self.list_view.setVisible(True)
        self.tile_scroll.setVisible(False)
    
    def update_tile_view(self, artifacts=None):
        """Update the tile view with artifacts using ResponsiveGridWidget."""
        artifacts_to_display = artifacts if artifacts is not None else self.artifacts
        
        # Clear existing cards
        self.tile_widget.clear_cards()
        
        # For large datasets, implement pagination
        max_items_per_page = 100
        total_items = len(artifacts_to_display)
        
        if total_items > max_items_per_page:
            if hasattr(self, 'pagination_widget'):
                self.add_pagination_controls(total_items, max_items_per_page)
            start_idx = self.current_page * max_items_per_page
            end_idx = min(start_idx + max_items_per_page, total_items)
            artifacts_to_display = artifacts_to_display[start_idx:end_idx]
        else:
            if hasattr(self, 'pagination_widget'):
                self.pagination_widget.setVisible(False)
        
        # Add artifacts as cards
        for artifact in artifacts_to_display:
            tile = self.create_tile_widget(artifact)
            self.tile_widget.add_card(tile)
        
        # Relayout cards
        self.tile_widget.relayout_cards()
        
        # Show tile view
        self.tile_scroll.setVisible(True)
        self.list_view.setVisible(False)
    
    def create_tile_widget(self, artifact):
        """Create a tile widget matching POC design exactly."""
        frame = QFrame()
        frame.setFrameStyle(QFrame.StyledPanel)
        frame.setCursor(Qt.PointingHandCursor)
        frame.setFixedSize(150, 175)
        
        is_directory = artifact.get('r_file_is_directory', False)
        is_recoverable = artifact.get('r_file_recovered', False)
        
        # Colors: green=recoverable (including folders), red=non-recoverable
        if is_recoverable:
            border_color = "#2da44e" if not self.is_dark_mode else "#238636"
            hover_border = "#2c974b" if not self.is_dark_mode else "#2ea043"
        else:
            border_color = "#cf222e" if not self.is_dark_mode else "#da3633"
            hover_border = "#a40e26" if not self.is_dark_mode else "#f85149"
        
        bg_color = "#ffffff" if not self.is_dark_mode else "#161b22"
        hover_bg = "#f6f8fa" if not self.is_dark_mode else "#1c2128"
        text_color = "#1a202c" if not self.is_dark_mode else "#f0f6fc"
        meta_color = "#57606a" if not self.is_dark_mode else "#8b949e"
        date_color = "#656d76" if not self.is_dark_mode else "#7d8590"
        checkbox_border = "#d0d7de" if not self.is_dark_mode else "#484f58"
        checkbox_bg = "#ffffff" if not self.is_dark_mode else "#0d1117"
        panel_bg = "#f8fafc" if not self.is_dark_mode else "#111827"
        inner_border = "#d0d7de" if not self.is_dark_mode else "#30363d"
        
        # Use object name to target only the outer frame, not inner QFrames
        # Add subtle shadow effect via styling
        shadow_color = "rgba(0,0,0,0.08)" if not self.is_dark_mode else "rgba(0,0,0,0.3)"
        frame.setObjectName("tileFrame")
        frame.setStyleSheet(f"""
            QFrame#tileFrame {{
                background-color: {bg_color};
                border: 2px solid {border_color};
                border-radius: 10px;
            }}
            QFrame#tileFrame:hover {{
                background-color: {hover_bg};
                border: 2px solid {hover_border};
            }}
            QToolTip {{
                background-color: #24292f;
                color: #ffffff;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
                font-size: 11px;
            }}
        """)
        
        # Main layout
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(4)
        
        # Checkbox at top-left
        checkbox = QCheckBox()
        checkbox.setFixedSize(18, 18)
        checkbox.setChecked(artifact in self.selected_artifacts)
        checkbox.stateChanged.connect(lambda state, a=artifact: self.on_artifact_selection_changed(a, state))
        checkbox.setStyleSheet(f"""
            QCheckBox::indicator {{
                width: 14px;
                height: 14px;
                border-radius: 3px;
                border: 1.5px solid {checkbox_border};
                background: {checkbox_bg};
            }}
            QCheckBox::indicator:hover {{
                border-color: #0969da;
            }}
            QCheckBox::indicator:checked {{
                background: #0969da;
                border-color: #0969da;
            }}
        """)
        layout.addWidget(checkbox, alignment=Qt.AlignLeft)
        
        # Icon block with soft background
        file_name = os.path.basename(artifact['original_path'])
        file_ext = artifact.get('file_ext', '').lower()
        

        icon_bg = "#f6f8fa" if not self.is_dark_mode else "#0f172a"
        icon_frame = QFrame()
        icon_frame.setFixedHeight(65)
        icon_frame.setStyleSheet(f"background-color: {icon_bg}; border: 1px solid {inner_border}; border-radius: 6px;")
        icon_layout = QVBoxLayout(icon_frame)
        icon_layout.setContentsMargins(0, 6, 0, 6)

        icon_label = QLabel()
        icon_label.setAlignment(Qt.AlignCenter)
        icon_label.setStyleSheet("background: transparent;")
        icon = self.item_delegate.get_file_type_icon(file_ext, is_directory)
        icon_label.setPixmap(icon.pixmap(48, 48))
        icon_layout.addWidget(icon_label)

        layout.addWidget(icon_frame)

        # Filename label with middle ellipsis for long names
        # Show start and end of filename so extension is visible
        def shorten_middle(name, max_len=40):
            if len(name) <= max_len:
                return name
            # Split to show start...end (preserve extension)
            start_len = 24  # Show first 24 chars
            end_len = 12    # Show last 12 chars (usually includes extension)
            return f"{name[:start_len]}...{name[-end_len:]}"

        file_name_display = shorten_middle(file_name)
        name_label = QLabel(file_name_display)
        name_label.setAlignment(Qt.AlignCenter)
        name_label.setWordWrap(True)
        name_label.setFixedWidth(130)
        name_label.setMinimumHeight(32)
        name_label.setMaximumHeight(48)
        name_label.setStyleSheet(f"font-size: 10px; font-weight: 600; color: {text_color}; background: transparent; border: none;")

        # Force a light-colored tooltip so it stays readable on the dark tooltip background in light mode
        safe_path = (
            artifact['original_path']
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
        #name_label.setToolTip(f"<span style='color:#f8fafc;'>{safe_path}</span>")
        name_label.setToolTip(f"<div style='color:#f8fafc; white-space: pre; display: inline-block;'>{safe_path}</div>")
        layout.addWidget(name_label, 0, Qt.AlignCenter)

        # Metadata block (size + date) with subtle border
        meta_block = QFrame()
        meta_block.setStyleSheet(f"background-color: {panel_bg}; border: 1px solid {inner_border}; border-radius: 4px;")
        meta_layout = QVBoxLayout(meta_block)
        meta_layout.setContentsMargins(4, 4, 4, 4)
        meta_layout.setSpacing(2)

        if is_directory:
            # For folders, show "Folder" label instead of size
            folder_label = QLabel("📁 Folder")
            folder_label.setAlignment(Qt.AlignCenter)
            folder_label.setStyleSheet(f"font-size: 10px; color: {meta_color}; background: transparent;")
            meta_layout.addWidget(folder_label)
        else:
            size_text = self.item_delegate.format_file_size(artifact['original_size'])
            size_label = QLabel(size_text)
            size_label.setAlignment(Qt.AlignCenter)
            size_label.setStyleSheet(f"font-size: 10px; color: {meta_color}; background: transparent;")
            meta_layout.addWidget(size_label)

        if artifact.get('deletion_time'):
            date_text = self.format_datetime_tz(artifact['deletion_time'], include_tz_label=False)
            date_text = date_text.split(' ')[0] if date_text else ""
            if date_text:
                date_label = QLabel(f"🗑 {date_text}")
                date_label.setAlignment(Qt.AlignCenter)
                date_label.setStyleSheet(f"font-size: 9px; color: {date_color}; background: transparent;")
                try:
                    utc_text = artifact['deletion_time'].astimezone(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
                except Exception:
                    utc_text = str(artifact.get('deletion_time', ''))
                local_text = self.format_datetime_tz(artifact['deletion_time'], include_tz_label=True)

                tip_color = "#e5e7eb"

                # Avoid duplicate line when current timezone is UTC
                #lines = [f"Deleted (UTC): {utc_text}"]
                if str(self.current_timezone).upper() != "UTC":
                    line = f"Deleted ({self.current_timezone}): {local_text}"
                else:
                    line = f"Deleted (UTC): {utc_text}"

                # tooltip_html = (
                    # f"<div style='color:{tip_color}; font-size:11px;'>"
                     # + "<br>".join(lines) +
                    # "</div>"
                # )
                tooltip_html = f"<div style='color:{tip_color}; font-size:11px; white-space:nowrap;'>{line}</div>"
                date_label.setToolTip(tooltip_html)
                meta_layout.addWidget(date_label)

        layout.addWidget(meta_block)
        
        # Tooltip with detailed info
        status = "Recoverable" if is_recoverable else "Non-recoverable"
        date_str = self.format_datetime_tz(artifact.get('deletion_time')) or "Unknown"
        if is_directory:
            frame.setToolTip(f"📁 Folder: {file_name}\nDeleted: {date_str}\nStatus: {status}\n\n💡 Double-click to browse contents")
        else:
            size_text = self.item_delegate.format_file_size(artifact['original_size'])
            frame.setToolTip(f"{file_name}\nSize: {size_text}\nDeleted: {date_str}\nStatus: {status}")
        
        # Connect signals
        if is_directory:
            frame.mouseDoubleClickEvent = lambda event, a=artifact: self.browse_folder(a)
        else:
            frame.mouseDoubleClickEvent = lambda event, a=artifact: self.show_file_details(a)
        
        frame.contextMenuEvent = lambda event, a=artifact: self.show_file_context_menu(event, a)
        
        return frame
    
    def browse_folder(self, folder_artifact):
        """Browse contents of a deleted folder."""
        if not folder_artifact.get('r_file_is_directory', False):
            return
        
        # Add to navigation stack
        self.folder_navigation_stack.append({
            'artifacts': self.artifacts.copy(),
            'title': self.title_label.text(),
            'folder': self.current_folder,
            'tree_context': getattr(self, 'current_tree_context', 'root')
        })

        self.current_tree_context = "root"
        
        # Show loading message
        self.statusBar.showMessage(f"Loading folder contents: {os.path.basename(folder_artifact['original_path'])}...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        # Load folder contents in background
        self.folder_worker = FolderContentWorker(self.parser, folder_artifact)
        self.folder_worker.content_ready.connect(lambda contents: self.on_folder_contents_loaded(folder_artifact, contents))
        self.folder_worker.start()
    
    def on_folder_contents_loaded(self, folder_artifact, contents):
        """Handle folder contents loaded."""
        self.progress_bar.setVisible(False)
        
        if not contents:
            QMessageBox.information(self, "Empty Folder", 
                                  f"The folder '{os.path.basename(folder_artifact['original_path'])}' appears to be empty or could not be read.")
            return
        
        # Update current folder
        self.current_folder = folder_artifact['original_path']
        
        # Show breadcrumb navigation
        self.breadcrumb_widget.setVisible(True)
        self.breadcrumb_label.setText(f"Browsing: {folder_artifact['original_path']}")
        self.breadcrumb_label.setToolTip(folder_artifact['original_path'])
        
        # Update artifacts to show folder contents
        self.artifacts = contents
        # Keep selected_artifacts - don't clear on folder navigation

        self.current_tree_context = "root"
        
        # Reset pagination
        self.current_page = 0
        
        # Update view
        self.apply_current_filters()
        
        self.statusBar.showMessage(f"Loaded {len(contents)} items from folder: {os.path.basename(folder_artifact['original_path'])}")
    
    def navigate_back(self):
        """Navigate back to previous view."""
        if not self.folder_navigation_stack:
            return
        
        # Restore previous state
        previous_state = self.folder_navigation_stack.pop()
        self.artifacts = previous_state['artifacts']
        self.current_folder = previous_state['folder']
        self.current_tree_context = previous_state.get('tree_context', 'root')
        # Keep selected_artifacts - don't clear on back navigation
        
        # Reset pagination
        self.current_page = 0
        
        # Hide breadcrumb if back to root
        if not self.folder_navigation_stack:
            self.breadcrumb_widget.setVisible(False)
        else:
            # Update breadcrumb
            self.breadcrumb_label.setText(f"Browsing: {self.current_folder}")
            self.breadcrumb_label.setToolTip(str(self.current_folder) if self.current_folder is not None else "")
        
        # Update view using proper filter application
        self.apply_current_filters()
        
        self.statusBar.showMessage("Navigated back to previous view.")
    
    def add_pagination_controls(self, total_items, items_per_page):
        """Add pagination controls for large datasets."""
        total_pages = (total_items + items_per_page - 1) // items_per_page
        
        # Create pagination widget if it doesn't exist
        if not hasattr(self, 'pagination_widget'):
            self.pagination_widget = QWidget()
            pagination_layout = QHBoxLayout(self.pagination_widget)
            pagination_layout.setContentsMargins(10, 10, 10, 10)
            
            self.prev_button = QPushButton("◀ Previous")
            self.prev_button.clicked.connect(self.previous_page)
            self.prev_button.setStyleSheet("""
                QPushButton {
                    background-color: #6c757d;
                    color: white;
                    border: none;
                    padding: 8px 15px;
                    border-radius: 4px;
                    font-size: 12px;
                }
                QPushButton:hover {
                    background-color: #5a6268;
                }
                QPushButton:disabled {
                    background-color: #e9ecef;
                    color: #6c757d;
                }
            """)
            pagination_layout.addWidget(self.prev_button)
            
            self.page_label = QLabel()
            self.page_label.setStyleSheet("font-weight: bold; color: #495057; margin: 0 15px;")
            pagination_layout.addWidget(self.page_label)
            
            self.next_button = QPushButton("Next ▶")
            self.next_button.clicked.connect(self.next_page)
            self.next_button.setStyleSheet("""
                QPushButton {
                    background-color: #6c757d;
                    color: white;
                    border: none;
                    padding: 8px 15px;
                    border-radius: 4px;
                    font-size: 12px;
                }
                QPushButton:hover {
                    background-color: #5a6268;
                }
                QPushButton:disabled {
                    background-color: #e9ecef;
                    color: #6c757d;
                }
            """)
            pagination_layout.addWidget(self.next_button)
            
            pagination_layout.addStretch()
            
            # Add to main layout
            self.view_stack.layout().addWidget(self.pagination_widget)

        if self.current_page < 0:
            self.current_page = 0
        if total_pages > 0 and self.current_page >= total_pages:
            self.current_page = max(0, total_pages - 1)
        self.page_label.setText(f"Page {self.current_page + 1} of {total_pages} ({total_items} total files)")
        self.prev_button.setEnabled(self.current_page > 0)
        self.next_button.setEnabled(self.current_page < total_pages - 1)
        self.pagination_widget.setVisible(True)
    def apply_dark_theme(self):
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(15, 23, 42))
        palette.setColor(QPalette.WindowText, QColor(226, 232, 240))
        palette.setColor(QPalette.Base, QColor(11, 18, 32))
        palette.setColor(QPalette.AlternateBase, QColor(17, 24, 39))
        palette.setColor(QPalette.ToolTipBase, QColor(50, 50, 50))  # Dark gray tooltip bg
        palette.setColor(QPalette.ToolTipText, QColor(255, 255, 255))  # White tooltip text
        palette.setColor(QPalette.Text, QColor(226, 232, 240))
        palette.setColor(QPalette.Button, QColor(17, 24, 39))
        palette.setColor(QPalette.ButtonText, QColor(226, 232, 240))
        palette.setColor(QPalette.Highlight, QColor(59, 130, 246))
        palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
        palette.setColor(QPalette.Link, QColor(96, 165, 250))
        palette.setColor(QPalette.LinkVisited, QColor(129, 140, 248))
        QApplication.setPalette(palette)

        self.setStyleSheet("""
            /* Tooltip - dark background */
            QToolTip {
                background-color: #24292f;
                color: #ffffff;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px 12px;
                font-size: 11px;
            }
            QToolTip QLabel {
                color: #ffffff;
            }

            QMainWindow {
                background-color: #0f172a;
            }

            QToolBar {
                background-color: #111827;
                border: none;
                border-bottom: 1px solid #1f2937;
                padding: 8px 12px;
                spacing: 4px;
            }
            QToolBar QToolButton {
                background-color: transparent;
                border: none;
                border-radius: 8px;
                padding: 8px 10px;
                margin: 0px 2px;
                color: #e2e8f0;
                font-weight: 500;
                min-height: 50px;
            }
            QToolBar QToolButton:hover {
                background-color: #1f2937;
                color: #ffffff;
            }
            QToolBar QToolButton:pressed {
                background-color: #334155;
            }
            QToolBar QToolButton:disabled {
                color: #64748b;
            }
            QToolBar QLabel {
                color: #e2e8f0;
                font-weight: 600;
                padding: 0 4px;
            }
            QToolBar QLabel#partitionLabel {
                color: #e2e8f0;
                font-weight: 600;
            }

            QComboBox {
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 8px 12px;
                padding-right: 30px;
                background-color: #0b1220;
                color: #e2e8f0;
                font-size: 13px;
                min-height: 20px;
            }
            QComboBox:hover {
                border-color: #475569;
                background-color: #0f172a;
            }
            QComboBox:focus {
                border-color: #3b82f6;
                outline: none;
            }
            QComboBox:disabled {
                background-color: #111827;
                color: #64748b;
                border-color: #1f2937;
            }
            QComboBox QAbstractItemView {
                background-color: #0b1220;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 4px;
                selection-background-color: #3b82f6;
                selection-color: #ffffff;
                outline: none;
            }
            QComboBox QAbstractItemView::item {
                padding: 8px 12px;
                min-height: 28px;
                color: #e2e8f0;
                background-color: #0b1220;
                border-radius: 4px;
                margin: 2px;
            }
            QComboBox QAbstractItemView::item:hover {
                background-color: #111827;
                color: #ffffff;
            }
            QComboBox QAbstractItemView::item:selected {
                background-color: #3b82f6;
                color: #ffffff;
            }

            QLineEdit {
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 8px 12px;
                background-color: #0b1220;
                color: #e2e8f0;
                font-size: 13px;
                selection-background-color: #3b82f6;
                selection-color: #ffffff;
            }
            QLineEdit:hover {
                border-color: #475569;
            }
            QLineEdit:focus {
                border-color: #3b82f6;
                outline: none;
            }
            QLineEdit::placeholder {
                color: #64748b;
            }

            QLabel {
                color: #cbd5e1;
                font-size: 13px;
            }

            QStatusBar {
                background-color: #111827;
                border-top: 1px solid #1f2937;
                color: #94a3b8;
                padding: 4px 12px;
                font-size: 12px;
            }
            QStatusBar::item {
                border: none;
            }

            QProgressBar {
                border: none;
                border-radius: 4px;
                background-color: #334155;
                text-align: center;
                color: #e2e8f0;
                font-size: 11px;
                font-weight: 500;
                min-height: 8px;
                max-height: 8px;
            }
            QProgressBar::chunk {
                background-color: #3b82f6;
                border-radius: 4px;
            }

            QSplitter::handle {
                background-color: #1f2937;
                width: 2px;
            }
            QSplitter::handle:hover {
                background-color: #3b82f6;
            }

            QMessageBox {
                background-color: #0f172a;
            }
            QMessageBox QLabel {
                color: #e2e8f0;
                font-size: 13px;
            }
            QMessageBox QPushButton {
                background-color: #3b82f6;
                color: #ffffff;
                border: none;
                border-radius: 6px;
                padding: 8px 20px;
                font-weight: 500;
                min-width: 80px;
            }
            QMessageBox QPushButton:hover {
                background-color: #2563eb;
            }

            QMenu {
                background-color: #0b1220;
                border: 1px solid #334155;
                border-radius: 8px;
                padding: 6px;
            }
            QMenu::item {
                padding: 8px 24px 8px 12px;
                border-radius: 4px;
                color: #e2e8f0;
            }
            QMenu::item:selected {
                background-color: #111827;
            }
            QMenu::separator {
                height: 1px;
                background-color: #1f2937;
                margin: 4px 8px;
            }
        """)

    def apply_current_theme(self):
        if self.is_dark_mode:
            self.apply_dark_theme()
        else:
            self.apply_modern_theme()

        if hasattr(self, "left_widget"):
            if self.is_dark_mode:
                self.left_widget.setStyleSheet("""
                    QWidget {
                        background-color: #0b1220;
                        border-right: 1px solid #1f2937;
                    }
                """)
                self.tree_header_widget.setStyleSheet("""
                    QWidget {
                        background-color: #1d4ed8;
                        border: none;
                    }
                """)
                self.tree_view.setStyleSheet("""
                    QTreeView {
                        border: none;
                        background-color: #0b1220;
                        selection-background-color: #3b82f6;
                        selection-color: white;
                        font-size: 11px;
                        font-family: "Segoe UI", Arial, sans-serif;
                        outline: none;
                        alternate-background-color: #0f172a;
                    }
                    QTreeView::item {
                        padding: 2px 4px;
                        min-height: 20px;
                        color: #e2e8f0;
                    }
                    QTreeView::item:hover {
                        background-color: #111827;
                    }
                    QTreeView::item:selected {
                        background-color: #3b82f6;
                        color: white;
                    }
                    QTreeView::item:selected:!active {
                        background-color: #1f2937;
                        color: #e2e8f0;
                    }
                    QHeaderView::section {
                        background-color: #1f2937;
                        color: #e2e8f0;
                        font-weight: bold;
                        font-size: 11px;
                        padding: 4px 8px;
                        border: none;
                        border-right: 1px solid #374151;
                        border-bottom: 1px solid #374151;
                    }
                """)
                self.right_widget.setStyleSheet("background-color: #0b1220;")
                self.file_list_header.setStyleSheet("""
                    QWidget {
                        background-color: #1d4ed8;
                        border: none;
                    }
                """)
                self.content_widget.setStyleSheet("background-color: #0f172a;")
                self.tile_scroll.setStyleSheet("""
                    QScrollArea {
                        border: none;
                        background-color: #0d1117;
                    }
                    QScrollArea > QWidget > QWidget {
                        background-color: #0d1117;
                    }
                """)
                self.tile_widget.setStyleSheet("background-color: #0d1117;")
                self.list_view.setStyleSheet("""
                    QListView {
                        border: 1px solid #1f2937;
                        border-radius: 12px;
                        background-color: #0b1220;
                        selection-background-color: #3b82f6;
                        selection-color: white;
                        padding: 8px;
                        color: #e2e8f0;
                    }
                    QListView::item {
                        border-radius: 6px;
                        padding: 8px;
                        margin: 2px 4px;
                    }
                    QListView::item:hover {
                        background-color: #111827;
                    }
                    QListView::item:selected {
                        background-color: #3b82f6;
                        color: white;
                    }
                """)
                if hasattr(self, "breadcrumb_widget"):
                    self.breadcrumb_widget.setStyleSheet("""
                        QWidget {
                            background-color: #111827;
                            border-radius: 8px;
                            padding: 4px;
                        }
                    """)
                # Dark mode for date pickers
                if hasattr(self, "date_from") and hasattr(self, "date_to"):
                    dark_date_style = """
                        QDateEdit {
                            border: 1px solid #374151;
                            border-radius: 4px;
                            padding: 4px 8px;
                            background-color: #1f2937;
                            color: #e2e8f0;
                        }
                        QDateEdit::drop-down {
                            subcontrol-origin: padding;
                            subcontrol-position: center right;
                            width: 20px;
                            border-left: 1px solid #374151;
                            background-color: #111827;
                        }
                        QDateEdit::down-arrow {
                            width: 12px;
                            height: 12px;
                            margin-right: 6px;
                            image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%23cbd5e1'><path d='M7 10l5 6 5-6H7z'/><rect x='10' y='4' width='4' height='6' rx='1' fill='%23cbd5e1'/></svg>");
                        }
                        QCalendarWidget {
                            background-color: #1f2937;
                        }
                        QCalendarWidget QToolButton {
                            color: #e2e8f0;
                            background-color: #374151;
                            border: none;
                            border-radius: 4px;
                            padding: 4px;
                            margin: 2px;
                        }
                        QCalendarWidget QToolButton:hover {
                            background-color: #4b5563;
                        }
                        QCalendarWidget QMenu {
                            background-color: #1f2937;
                            color: #e2e8f0;
                        }
                        QCalendarWidget QSpinBox {
                            background-color: #1f2937;
                            color: #e2e8f0;
                            border: 1px solid #374151;
                        }
                        QCalendarWidget QWidget#qt_calendar_navigationbar {
                            background-color: #374151;
                        }
                        QCalendarWidget QTableView {
                            background-color: #1f2937;
                            color: #e2e8f0;
                            selection-background-color: #3b82f6;
                            selection-color: white;
                        }
                        QCalendarWidget QTableView QHeaderView::section {
                            background-color: #374151;
                            color: #9ca3af;
                            padding: 4px;
                        }
                    """
                    self.date_from.setStyleSheet(dark_date_style)
                    self.date_to.setStyleSheet(dark_date_style)
                # Dark mode for timezone combo
                if hasattr(self, "tz_combo"):
                    self.tz_combo.setStyleSheet("""
                        QComboBox {
                            border: 1px solid #374151;
                            border-radius: 4px;
                            padding: 4px 8px;
                            background-color: #1f2937;
                            color: #e2e8f0;
                            min-width: 120px;
                        }
                        QComboBox QAbstractItemView {
                            background-color: #1f2937;
                            color: #e2e8f0;
                            selection-background-color: #3b82f6;
                            selection-color: white;
                        }
                    """)
                # Dark mode for title and header labels
                if hasattr(self, "title_label"):
                    self.title_label.setStyleSheet("color: #f1f5f9; background: transparent;")
                if hasattr(self, "sort_label"):
                    self.sort_label.setStyleSheet("color: #9ca3af; background: transparent;")
                # Dark mode for filter/date labels
                for label_name in ["date_filter_label", "date_from_label", "date_to_label", "tz_label_widget"]:
                    if hasattr(self, label_name):
                        getattr(self, label_name).setStyleSheet("color: #9ca3af; background: transparent;")
                # Dark mode for sort combo
                if hasattr(self, "sort_combo"):
                    self.sort_combo.setStyleSheet("""
                        QComboBox {
                            border: 1px solid #374151;
                            border-radius: 4px;
                            padding: 6px 28px 6px 10px;
                            background-color: #1f2937;
                            color: #e2e8f0;
                            font-size: 12px;
                        }
                        QComboBox QAbstractItemView {
                            background-color: #1f2937;
                            color: #e2e8f0;
                            selection-background-color: #3b82f6;
                            selection-color: white;
                            border: 1px solid #374151;
                        }
                    """)
            else:
                self.left_widget.setStyleSheet("""
                    QWidget {
                        background-color: #ffffff;
                        border-right: 1px solid #c0c0c0;
                    }
                """)
                self.tree_header_widget.setStyleSheet("""
                    QWidget {
                        background-color: #0078d4;
                        border: none;
                    }
                """)
                self.tree_view.setStyleSheet("""
                    QTreeView {
                        border: none;
                        background-color: #ffffff;
                        selection-background-color: #0078d4;
                        selection-color: white;
                        font-size: 11px;
                        font-family: "Segoe UI", Arial, sans-serif;
                        outline: none;
                        show-decoration-selected: 1;
                    }
                    QTreeView::item {
                        padding: 2px 4px;
                        min-height: 20px;
                    }
                    QTreeView::item:hover {
                        background-color: #e5f3ff;
                    }
                    QTreeView::item:selected {
                        background-color: #0078d4;
                        color: white;
                    }
                    QTreeView::item:selected:!active {
                        background-color: #cce8ff;
                        color: black;
                    }
                    QHeaderView::section {
                        background-color: #f0f0f0;
                        color: #333333;
                        font-weight: bold;
                        font-size: 11px;
                        padding: 4px 8px;
                        border: none;
                        border-right: 1px solid #c0c0c0;
                        border-bottom: 1px solid #c0c0c0;
                    }
                """)
                self.right_widget.setStyleSheet("background-color: #ffffff;")
                self.file_list_header.setStyleSheet("""
                    QWidget {
                        background-color: #0078d4;
                        border: none;
                    }
                """)
                self.content_widget.setStyleSheet("background-color: #f5f7fa;")
                self.tile_scroll.setStyleSheet("""
                    QScrollArea {
                        border: none;
                        background-color: #f6f8fa;
                    }
                    QScrollArea > QWidget > QWidget {
                        background-color: #f6f8fa;
                    }
                """)
                self.tile_widget.setStyleSheet("background-color: #f6f8fa;")
                self.list_view.setStyleSheet("""
                    QListView {
                        border: 1px solid #e2e8f0;
                        border-radius: 12px;
                        background-color: #ffffff;
                        selection-background-color: #4f46e5;
                        selection-color: white;
                        padding: 8px;
                    }
                    QListView::item {
                        border-radius: 6px;
                        padding: 8px;
                        margin: 2px 4px;
                    }
                    QListView::item:hover {
                        background-color: #f1f5f9;
                    }
                    QListView::item:selected {
                        background-color: #4f46e5;
                        color: white;
                    }
                """)
                if hasattr(self, "breadcrumb_widget"):
                    self.breadcrumb_widget.setStyleSheet("""
                        QWidget {
                            background-color: #f1f5f9;
                            border-radius: 8px;
                            padding: 4px;
                        }
                    """)
                # Light mode for date pickers
                if hasattr(self, "date_from") and hasattr(self, "date_to"):
                    light_date_style = """
                        QDateEdit {
                            border: 1px solid #cbd5e1;
                            border-radius: 4px;
                            padding: 4px 8px;
                            background-color: white;
                            color: #1e293b;
                        }
                        QDateEdit::drop-down {
                            subcontrol-origin: padding;
                            subcontrol-position: center right;
                            width: 20px;
                            border-left: 1px solid #cbd5e1;
                        }
                        QCalendarWidget {
                            background-color: white;
                        }
                        QCalendarWidget QToolButton {
                            color: #1e293b;
                            background-color: #f1f5f9;
                            border: none;
                            border-radius: 4px;
                            padding: 4px;
                            margin: 2px;
                        }
                        QCalendarWidget QToolButton:hover {
                            background-color: #e2e8f0;
                        }
                        QCalendarWidget QMenu {
                            background-color: white;
                            color: #1e293b;
                        }
                        QCalendarWidget QSpinBox {
                            background-color: white;
                            color: #1e293b;
                            border: 1px solid #cbd5e1;
                        }
                        QCalendarWidget QWidget#qt_calendar_navigationbar {
                            background-color: #f1f5f9;
                        }
                        QCalendarWidget QTableView {
                            background-color: white;
                            selection-background-color: #0078d4;
                            selection-color: white;
                        }
                        QCalendarWidget QTableView QHeaderView::section {
                            background-color: #f1f5f9;
                            color: #475569;
                            padding: 4px;
                        }
                    """
                    self.date_from.setStyleSheet(light_date_style)
                    self.date_to.setStyleSheet(light_date_style)
                # Light mode for timezone combo
                if hasattr(self, "tz_combo"):
                    self.tz_combo.setStyleSheet("""
                        QComboBox {
                            border: 1px solid #cbd5e1;
                            border-radius: 4px;
                            padding: 4px 8px;
                            background-color: white;
                            color: #1e293b;
                            min-width: 120px;
                        }
                        QComboBox QAbstractItemView {
                            background-color: white;
                            selection-background-color: #0078d4;
                            selection-color: white;
                        }
                    """)
                # Light mode for title and header labels
                if hasattr(self, "title_label"):
                    self.title_label.setStyleSheet("color: #1e293b; background: transparent;")
                if hasattr(self, "sort_label"):
                    self.sort_label.setStyleSheet("color: #64748b; background: transparent;")
                # Light mode for filter/date labels
                for label_name in ["date_filter_label", "date_from_label", "date_to_label", "tz_label_widget"]:
                    if hasattr(self, label_name):
                        getattr(self, label_name).setStyleSheet("color: #64748b; background: transparent;")
                # Light mode for sort combo
                if hasattr(self, "sort_combo"):
                    self.sort_combo.setStyleSheet("""
                        QComboBox {
                            border: 1px solid #cbd5e1;
                            border-radius: 4px;
                            padding: 6px 28px 6px 10px;
                            background-color: white;
                            color: #1e293b;
                            font-size: 12px;
                        }
                        QComboBox QAbstractItemView {
                            background-color: white;
                            selection-background-color: #0078d4;
                            selection-color: white;
                            border: 1px solid #cbd5e1;
                        }
                    """)

    def set_dark_mode(self, enabled):
        self.is_dark_mode = bool(enabled)
        if hasattr(self, "dark_mode_action") and self.dark_mode_action.isChecked() != self.is_dark_mode:
            self.dark_mode_action.blockSignals(True)
            self.dark_mode_action.setChecked(self.is_dark_mode)
            self.dark_mode_action.blockSignals(False)
        self.apply_current_theme()
        # Refresh file view to apply theme to tiles
        if hasattr(self, "artifacts") and self.artifacts:
            self.apply_current_filters()
        self.save_ui_settings()

    def set_view_mode(self, mode):
        if mode not in ("tiles", "list"):
            return
        if self.current_view_mode != mode:
            self.toggle_view()
        if hasattr(self, "list_view_action") and hasattr(self, "tile_view_action"):
            self.list_view_action.blockSignals(True)
            self.tile_view_action.blockSignals(True)
            self.list_view_action.setChecked(self.current_view_mode == "list")
            self.tile_view_action.setChecked(self.current_view_mode == "tiles")
            self.list_view_action.blockSignals(False)
            self.tile_view_action.blockSignals(False)
        self.save_ui_settings()

    def load_ui_settings(self):
        theme = self.settings.value("ui/theme", "light")
        self.is_dark_mode = (str(theme).lower() == "dark")

        view_mode = self.settings.value("ui/view_mode", "tiles")
        view_mode = str(view_mode).lower()
        if view_mode not in ("tiles", "list"):
            view_mode = "tiles"
        
        # Load timezone setting
        saved_tz = self.settings.value("ui/timezone", "UTC")
        if saved_tz in self.available_timezones:
            self.current_timezone = saved_tz
        if hasattr(self, "tz_combo"):
            self.tz_combo.blockSignals(True)
            self.tz_combo.setCurrentText(self.current_timezone)
            self.tz_combo.blockSignals(False)

        geometry = self.settings.value("ui/geometry")
        if geometry is not None:
            try:
                self.restoreGeometry(geometry)
            except Exception:
                pass

        window_state = self.settings.value("ui/window_state")
        if window_state is not None:
            try:
                self.restoreState(window_state)
            except Exception:
                pass

        splitter_sizes = self.settings.value("ui/splitter_sizes")
        if splitter_sizes:
            try:
                sizes = [int(s) for s in splitter_sizes]
                if sizes:
                    self.splitter.setSizes(sizes)
            except Exception:
                pass

        if hasattr(self, "dark_mode_action"):
            self.dark_mode_action.blockSignals(True)
            self.dark_mode_action.setChecked(self.is_dark_mode)
            self.dark_mode_action.blockSignals(False)

        self.apply_current_theme()
        self.set_view_mode(view_mode)

    def save_ui_settings(self):
        try:
            self.settings.setValue("ui/theme", "dark" if self.is_dark_mode else "light")
            self.settings.setValue("ui/view_mode", self.current_view_mode)
            self.settings.setValue("ui/timezone", self.current_timezone)
            if hasattr(self, "splitter"):
                self.settings.setValue("ui/splitter_sizes", self.splitter.sizes())
            self.settings.setValue("ui/geometry", self.saveGeometry())
            self.settings.setValue("ui/window_state", self.saveState())
        except Exception:
            pass

    def close_image(self):
        if self.is_processing_partition:
            QMessageBox.information(self, "Operation in Progress", "A partition is currently being processed. Please wait for it to finish.")
            return

        if hasattr(self, "load_image_thread") and self.load_image_thread.isRunning():
            QMessageBox.information(self, "Operation in Progress", "The image is currently being opened. Please wait for it to finish.")
            return

        self.ignore_background_results = True

        try:
            if self.export_worker and self.export_worker.isRunning():
                self.export_worker.cancel()
        except Exception:
            pass

        try:
            if self.hash_worker:
                self.hash_worker.stop()
        except Exception:
            pass

        try:
            if self.parser and getattr(self.parser, "img_info", None):
                self.parser.img_info.close()
        except Exception:
            pass

        self.parser = None
        self.image_path = None
        self.current_partition = None
        self.partition_cache.clear()
        self.is_processing_partition = False

        self.folder_navigation_stack = []
        self.current_folder = None
        self.current_partition = None
        self.partition_cache = {}
        self.current_timezone = "UTC"
        self.all_artifacts = []  # Keep full dataset for selection/export across navigation

        self.partition_combo.blockSignals(True)
        self.partition_combo.clear()
        self.partition_combo.blockSignals(False)
        self.partition_combo.setEnabled(False)

        self.clear_current_view()
        self.statusBar.showMessage("Ready. Open an E01 image to begin forensic analysis.")
        self.progress_bar.setVisible(False)

        self.export_action.setEnabled(False)
        self.export_all_action.setEnabled(False)
        self.report_action.setEnabled(False)
        self.stats_action.setEnabled(False)
        self.close_image_action.setEnabled(False)

        self.ignore_background_results = False

    def closeEvent(self, event):
        self.save_ui_settings()
        try:
            if self.hash_worker:
                self.hash_worker.stop()
        except Exception:
            pass
        try:
            if self.parser and getattr(self.parser, "img_info", None):
                self.parser.img_info.close()
        except Exception:
            pass
        super().closeEvent(event)

    def previous_page(self):
        """Go to previous page."""
        if self.current_page > 0:
            self.current_page -= 1
            self.update_file_view(self.get_displayed_artifacts())

    def next_page(self):
        """Go to next page."""
        self.current_page += 1
        self.update_file_view(self.get_displayed_artifacts())

    def on_artifact_selection_changed(self, artifact, state):
        """Handle artifact selection change."""
        # state is an int: 0 = Unchecked, 2 = Checked (Qt.CheckState values)
        is_checked = (state == 2)  # Qt.CheckState.Checked = 2

        if is_checked:
            if artifact not in self.selected_artifacts:
                self.selected_artifacts.append(artifact)
            # If folder is selected, also select all children
            if artifact.get('r_file_is_directory', False):
                self._select_folder_children(artifact)
        else:
            if artifact in self.selected_artifacts:
                self.selected_artifacts.remove(artifact)
            # If folder is deselected, also deselect all children
            if artifact.get('r_file_is_directory', False):
                self._deselect_folder_children(artifact)

        # Update selection count and export action
        self.update_selection_count()
    
    def _select_folder_children(self, folder_artifact):
        """Select all children of a folder (files and subfolders)."""
        folder_path = folder_artifact.get('original_path', '')
        if not folder_path:
            return
        
        # Find all artifacts that are children of this folder in existing lists
        all_artifacts = self.all_artifacts if hasattr(self, 'all_artifacts') and self.all_artifacts else self.artifacts
        children_found = False
        for artifact in all_artifacts:
            artifact_path = artifact.get('original_path', '')
            # Check if this artifact is inside the folder
            if artifact_path.startswith(folder_path + '\\') or artifact_path.startswith(folder_path + '/'):
                if artifact not in self.selected_artifacts:
                    self.selected_artifacts.append(artifact)
                children_found = True
        
        # If no children found in artifacts list, scan folder contents from parser
        if not children_found and self.parser and folder_artifact.get('r_file_recovered', False):
            try:
                folder_contents = self.parser.scan_folder_contents(folder_artifact)
                for child in folder_contents:
                    if child not in self.selected_artifacts:
                        self.selected_artifacts.append(child)
                logger.info(f"Auto-selected {len(folder_contents)} children from folder: {folder_path}")
            except Exception as e:
                logger.warning(f"Could not scan folder contents for selection: {e}")
    
    def _deselect_folder_children(self, folder_artifact):
        """Deselect all children of a folder."""
        folder_path = folder_artifact.get('original_path', '')
        if not folder_path:
            return
        
        # Remove all artifacts that are children of this folder
        children_to_remove = []
        for artifact in self.selected_artifacts:
            artifact_path = artifact.get('original_path', '')
            if artifact_path.startswith(folder_path + '\\') or artifact_path.startswith(folder_path + '/'):
                children_to_remove.append(artifact)
        
        for child in children_to_remove:
            self.selected_artifacts.remove(child)

    def on_list_selection_changed(self, selected, deselected):
        """Handle selection change in list view."""
        self.selected_artifacts = []

        # Get selected indexes
        for index in self.list_view.selectionModel().selectedIndexes():
            artifact = index.data(Qt.UserRole)
            if artifact:
                self.selected_artifacts.append(artifact)

        # Update selection count and export action
        self.update_selection_count()

    def toggle_view(self):
        """Toggle between tile and list view."""
        if self.current_view_mode == "tiles":
            self.current_view_mode = "list"
            self.view_action.setText("Tile View")
            self.view_action.setIcon(
                QIcon.fromTheme("view-grid", QApplication.style().standardIcon(QStyle.SP_FileDialogDetailedView))
            )
        else:
            self.current_view_mode = "tiles"
            self.view_action.setText("List View")
            self.view_action.setIcon(
                QIcon.fromTheme("view-list-icons", QApplication.style().standardIcon(QStyle.SP_FileDialogListView))
            )

        # Update view
        self.update_file_view(self.get_displayed_artifacts())

    def on_search_changed(self, text):
        """Handle search text change."""
        self.apply_current_filters()

    def on_filter_changed(self, filter_text):
        """Handle filter change."""
        self.apply_current_filters()
    
    def on_date_filter_changed(self, date):
        """Handle date filter change."""
        self.apply_current_filters()
    
    def clear_date_filter(self):
        """Clear the date range filter."""
        from PySide6.QtCore import QDate
        self.date_from.blockSignals(True)
        self.date_to.blockSignals(True)
        self.date_from.setDate(QDate(2000, 1, 1))
        self.date_to.setDate(QDate.currentDate())
        self.date_from.blockSignals(False)
        self.date_to.blockSignals(False)
        self.apply_current_filters()
    
    def on_timezone_changed(self, tz_text):
        """Handle timezone change."""
        self.current_timezone = tz_text
        self.save_ui_settings()
        # Refresh the view to update displayed times
        self.update_file_view(self.get_displayed_artifacts())
    
    def format_datetime_tz(self, dt, include_tz_label=True):
        """Format a datetime object in the current timezone with optional label."""
        if dt is None:
            return ""
        try:
            # Assume input datetime is UTC (as stored in forensic artifacts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=ZoneInfo("UTC"))
            
            # Convert to target timezone
            target_tz = ZoneInfo(self.current_timezone)
            dt_converted = dt.astimezone(target_tz)
            
            # Format with timezone indicator
            if include_tz_label:
                if self.current_timezone == "UTC":
                    return dt_converted.strftime('%Y-%m-%d %H:%M:%S') + " (UTC)"
                else:
                    return dt_converted.strftime('%Y-%m-%d %H:%M:%S') + f" ({self.current_timezone})"
            else:
                return dt_converted.strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            # Fallback to simple string format
            if isinstance(dt, datetime.datetime):
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            return str(dt)

    def get_context_artifacts(self):
        if not self.artifacts:
            return []

        context = getattr(self, 'current_tree_context', 'root')
        if not context or context == "root":
            return self.artifacts

        if isinstance(context, str) and context.startswith("sid:"):
            _, sid = context.split(":", 1)
            return [a for a in self.artifacts if a.get('sid') == sid]

        if isinstance(context, str) and context.startswith("drive:"):
            parts = context.split(":", 2)
            if len(parts) == 3:
                _, sid, drive = parts
                return [
                    a for a in self.artifacts
                    if a.get('sid') == sid and str(a.get('original_path', '')).startswith(drive)
                ]
            return self.artifacts

        if isinstance(context, str) and context.startswith("dir:"):
            parts = context.split(":", 2)
            if len(parts) == 3:
                _, sid, path = parts
                target_dir = os.path.normcase(os.path.normpath(path))
                
                # First, find if this is a non-recoverable folder - if so, only show items that exactly match
                matching_artifacts = []
                for a in self.artifacts:
                    if a.get('sid') != sid:
                        continue
                    
                    artifact_path = os.path.normcase(os.path.normpath(a.get('original_path', '')))
                    artifact_dir = os.path.normcase(os.path.normpath(os.path.dirname(a.get('original_path', ''))))
                    
                    # Check if this artifact IS the folder itself (exact match)
                    if artifact_path == target_dir:
                        matching_artifacts.append(a)
                        continue
                    
                    # Check if artifact is INSIDE this folder (parent dir matches exactly or starts with target + separator)
                    if artifact_dir == target_dir:
                        matching_artifacts.append(a)
                    elif artifact_dir.startswith(target_dir + os.sep):
                        matching_artifacts.append(a)
                
                return matching_artifacts
            return self.artifacts

        return self.artifacts

    def apply_current_filters(self):
        """Apply current search and filter settings."""
        if not self.artifacts:
            return

        self.current_page = 0

        search_text = self.search_box.text().strip() if hasattr(self, 'search_box') else ""
        filter_text = self.filter_combo.currentText() if hasattr(self, 'filter_combo') else "All"

        filtered = self.get_context_artifacts()

        if filter_text and filter_text != "All":
            if filter_text == "Not Present":
                filtered = [a for a in filtered if not a.get('r_file_recovered')]
            else:
                filtered = [a for a in filtered if a.get('file_type') == filter_text]

        if search_text:
            search_lower = search_text.lower()
            filtered = [
                a for a in filtered
                if search_lower in os.path.basename(a['original_path']).lower()
                or search_lower in a['original_path'].lower()
            ]
        
        # Apply date range filter
        if hasattr(self, 'date_from') and hasattr(self, 'date_to'):
            from_date = self.date_from.date().toPython()
            to_date = self.date_to.date().toPython()
            
            def artifact_in_date_range(artifact):
                deletion_time = artifact.get('deletion_time')
                if deletion_time is None:
                    return True  # Include artifacts without deletion time
                # Convert datetime to date for comparison
                if isinstance(deletion_time, datetime.datetime):
                    artifact_date = deletion_time.date()
                else:
                    return True
                return from_date <= artifact_date <= to_date
            
            filtered = [a for a in filtered if artifact_in_date_range(a)]

        self.update_file_view(filtered)

    def on_sort_changed(self, sort_text):
        """Handle sort option change."""
        if not self.artifacts:
            return

        # Map sort options to column and order
        sort_map = {
            "Date (newest)": {"column": "deletion_time", "order": "descending"},
            "Date (oldest)": {"column": "deletion_time", "order": "ascending"},
            "Size (largest)": {"column": "original_size", "order": "descending"},
            "Size (smallest)": {"column": "original_size", "order": "ascending"},
            "Name (A-Z)": {"column": "name", "order": "ascending"},
            "Name (Z-A)": {"column": "name", "order": "descending"}
        }

        if sort_text in sort_map:
            sort_info = sort_map[sort_text]

            # Sort artifacts
            if sort_info["column"] == "name":
                # Sort by file name
                reverse = sort_info["order"] == "descending"
                self.artifacts.sort(
                    key=lambda a: os.path.basename(a.get('original_path', '')).lower(),
                    reverse=reverse
                )
            else:
                # Sort by other columns
                column = sort_info["column"]
                reverse = sort_info["order"] == "descending"
                self.artifacts.sort(
                    key=lambda a: a.get(column, 0) or 0,
                    reverse=reverse
                )

            # Update view
            self.apply_current_filters()

    def play_transition_effect(self):
        """Play a brief fade transition effect on the file view for visual feedback."""
        try:
            # Stop any existing animation first
            if hasattr(self, 'fade_animation') and self.fade_animation:
                self.fade_animation.stop()
            
            # Get the scroll area or file view widget
            target_widget = self.scroll_area if hasattr(self, 'scroll_area') else None
            if not target_widget:
                return
            
            # Clear any existing effect
            target_widget.setGraphicsEffect(None)
            
            # Create opacity effect
            opacity_effect = QGraphicsOpacityEffect(target_widget)
            target_widget.setGraphicsEffect(opacity_effect)
            
            # Create fade animation
            self.fade_animation = QPropertyAnimation(opacity_effect, b"opacity")
            self.fade_animation.setDuration(100)  # Reduced to 100ms for snappier feel
            self.fade_animation.setStartValue(0.6)
            self.fade_animation.setEndValue(1.0)
            self.fade_animation.setEasingCurve(QEasingCurve.OutCubic)
            
            # Clear effect after animation
            self.fade_animation.finished.connect(lambda: target_widget.setGraphicsEffect(None))
            self.fade_animation.start()
        except Exception:
            pass  # Silently ignore animation errors
    
    def on_tree_item_clicked(self, index):
        """Handle click on a tree item."""
        # Get item data
        item_data = index.data(Qt.UserRole)
        if not item_data:
            return
        
        # Check if this is a non-recoverable file item - do NOTHING
        if item_data.startswith("file:"):
            _, i_file_name = item_data.split(":", 1)
            source_artifacts = self.all_artifacts if hasattr(self, 'all_artifacts') and self.all_artifacts else self.artifacts
            for artifact in source_artifacts:
                if artifact['i_file_name'] == i_file_name:
                    # Non-recoverable items - do nothing, just ignore the click
                    if not artifact.get('r_file_recovered', False):
                        return  # Do nothing for non-recoverable items
                    # If it's a recoverable folder, browse into it
                    elif artifact.get('r_file_is_directory', False):
                        self.browse_folder(artifact)
                    return
            return
        
        # For other tree items, exit folder browse mode first
        if self.folder_navigation_stack:
            # Restore original artifacts list from cache
            if hasattr(self, 'all_artifacts') and self.all_artifacts:
                self.artifacts = self.all_artifacts.copy()
            self.folder_navigation_stack = []
            self.breadcrumb_widget.setVisible(False)
        
        # Play visual transition effect
        self.play_transition_effect()
        
        # Parse item data and filter artifacts accordingly
        if item_data == "root":
            # Show all artifacts
            self.current_folder = None
            self.current_tree_context = "root"
            self.apply_current_filters()
        elif item_data.startswith("sid:"):
            # Show artifacts for SID
            _, sid = item_data.split(":", 1)
            self.current_folder = sid
            self.current_tree_context = item_data
            self.apply_current_filters()
        elif item_data.startswith("drive:"):
            # Show artifacts for drive
            parts = item_data.split(":", 2)
            if len(parts) == 3:
                _, sid, drive = parts
                self.current_folder = drive
                self.current_tree_context = item_data
                self.apply_current_filters()
        elif item_data.startswith("dir:"):
            # Show artifacts for directory
            parts = item_data.split(":", 2)
            if len(parts) == 3:
                _, sid, path = parts
                self.current_folder = path
                self.current_tree_context = item_data
            else:
                _, path = item_data.split(":", 1)
                self.current_folder = path
                self.current_tree_context = item_data
            self.apply_current_filters()
    
    def on_item_double_clicked(self, index):
        """Handle double-click on a list item."""
        # Get artifact data
        artifact = index.data(Qt.UserRole)
        if artifact:
            if artifact.get('r_file_is_directory', False):
                self.browse_folder(artifact)
            else:
                self.show_file_details(artifact)
    
    def show_file_details(self, artifact):
        """Show detailed information about a file."""
        # Create dialog with current timezone
        dialog = FileDetailsDialog(self, artifact, self.parser, self.current_timezone)
        dialog.exec()
    
    def show_tree_context_menu(self, pos):
        """Show context menu for tree view."""
        # Get item at position
        index = self.tree_view.indexAt(pos)
        if not index.isValid():
            return
        
        # Get item data
        item_data = index.data(Qt.UserRole)
        if not item_data:
            return
        
        # Create menu
        menu = QMenu(self)
        # Theme-aware styling for readability in both light and dark modes
        if self.is_dark_mode:
            menu.setStyleSheet("""
                QMenu {
                    background-color: #0b1220;
                    border: 1px solid #334155;
                    border-radius: 8px;
                    padding: 6px;
                }
                QMenu::item {
                    padding: 8px 24px 8px 12px;
                    border-radius: 4px;
                    color: #e2e8f0;
                }
                QMenu::item:selected {
                    background-color: #111827;
                    color: #ffffff;
                }
                QMenu::separator {
                    height: 1px;
                    background-color: #1f2937;
                    margin: 4px 8px;
                }
            """)
        else:
            menu.setStyleSheet("""
                QMenu {
                    background-color: #ffffff;
                    border: 1px solid #ced4da;
                    border-radius: 5px;
                    padding: 5px;
                }
                QMenu::item {
                    padding: 8px 20px;
                    border-radius: 3px;
                    color: #1e293b;
                }
                QMenu::item:selected {
                    background-color: #007bff;
                    color: white;
                }
                QMenu::separator {
                    height: 1px;
                    background-color: #e2e8f0;
                    margin: 4px 8px;
                }
            """)
        
        # Add actions based on item type
        if item_data == "root":
            menu.addAction("Export All Files", lambda: self.export_tree_files(self.artifacts))
        elif item_data.startswith("sid:"):
            # SID folder
            _, sid = item_data.split(":", 1)
            filtered = [a for a in self.artifacts if a['sid'] == sid]
            menu.addAction(f"Export All Files in {sid}", lambda: self.export_tree_files(filtered))
        elif item_data.startswith("file:"):
            # File
            _, i_file_name = item_data.split(":", 1)
            for artifact in self.artifacts:
                if artifact['i_file_name'] == i_file_name:
                    menu.addAction("View Details", lambda a=artifact: self.show_file_details(a))
                    if artifact['r_file_recovered']:
                        menu.addAction("Export File", lambda a=artifact: self.export_single_file(a))
                    if artifact.get('r_file_is_directory', False):
                        menu.addAction("Browse Folder", lambda a=artifact: self.browse_folder(a))
                    break
        
        # Show menu
        if not menu.isEmpty():
            menu.exec(self.tree_view.viewport().mapToGlobal(pos))
    
    def show_list_context_menu(self, pos):
        """Show context menu for list view."""
        # Get item at position
        index = self.list_view.indexAt(pos)
        if not index.isValid():
            return
        
        # Get artifact data
        artifact = index.data(Qt.UserRole)
        if not artifact:
            return
        
        # Create menu
        menu = QMenu(self)
        # Theme-aware styling for readability in both light and dark modes
        if self.is_dark_mode:
            menu.setStyleSheet("""
                QMenu {
                    background-color: #0b1220;
                    border: 1px solid #334155;
                    border-radius: 8px;
                    padding: 6px;
                }
                QMenu::item {
                    padding: 8px 24px 8px 12px;
                    border-radius: 4px;
                    color: #e2e8f0;
                }
                QMenu::item:selected {
                    background-color: #111827;
                    color: #ffffff;
                }
                QMenu::separator {
                    height: 1px;
                    background-color: #1f2937;
                    margin: 4px 8px;
                }
            """)
        else:
            menu.setStyleSheet("""
                QMenu {
                    background-color: #ffffff;
                    border: 1px solid #ced4da;
                    border-radius: 5px;
                    padding: 5px;
                }
                QMenu::item {
                    padding: 8px 20px;
                    border-radius: 3px;
                    color: #1e293b;
                }
                QMenu::item:selected {
                    background-color: #007bff;
                    color: white;
                }
                QMenu::separator {
                    height: 1px;
                    background-color: #e2e8f0;
                    margin: 4px 8px;
                }
            """)
        
        # Add actions
        menu.addAction("View Details", lambda: self.show_file_details(artifact))
        # Export logic: Show "Export Selected" when 1+ files selected, "Export File" only when exactly 1 file
        if len(self.selected_artifacts) >= 1 and any(a.get('r_file_recovered') for a in self.selected_artifacts):
            menu.addAction("Export Selected", self.export_selected)
        elif artifact['r_file_recovered']:
            menu.addAction("Export File", lambda: self.export_single_file(artifact))
        if artifact.get('r_file_is_directory', False):
            menu.addAction("Browse Folder", lambda: self.browse_folder(artifact))
        
        # Add selection actions
        menu.addSeparator()
        menu.addAction("Select All", self.select_all)
        menu.addAction("Deselect All", self.deselect_all)
        
        # Show menu
        menu.exec(self.list_view.viewport().mapToGlobal(pos))
    
    def show_file_context_menu(self, event, artifact):
        """Show context menu for a file tile."""
        # Create menu
        menu = QMenu(self)
        # Theme-aware styling for readability in both light and dark modes
        if self.is_dark_mode:
            menu.setStyleSheet("""
                QMenu {
                    background-color: #0b1220;
                    border: 1px solid #334155;
                    border-radius: 8px;
                    padding: 6px;
                }
                QMenu::item {
                    padding: 8px 24px 8px 12px;
                    border-radius: 4px;
                    color: #e2e8f0;
                }
                QMenu::item:selected {
                    background-color: #111827;
                    color: #ffffff;
                }
                QMenu::separator {
                    height: 1px;
                    background-color: #1f2937;
                    margin: 4px 8px;
                }
            """)
        else:
            menu.setStyleSheet("""
                QMenu {
                    background-color: #ffffff;
                    border: 1px solid #ced4da;
                    border-radius: 5px;
                    padding: 5px;
                }
                QMenu::item {
                    padding: 8px 20px;
                    border-radius: 3px;
                    color: #1e293b;
                }
                QMenu::item:selected {
                    background-color: #007bff;
                    color: white;
                }
                QMenu::separator {
                    height: 1px;
                    background-color: #e2e8f0;
                    margin: 4px 8px;
                }
            """)
        
        # Add actions
        menu.addAction("View Details", lambda: self.show_file_details(artifact))
        # Export logic: Show "Export Selected" when 1+ files selected, "Export File" only when exactly 1 file
        if len(self.selected_artifacts) >= 1 and any(a.get('r_file_recovered') for a in self.selected_artifacts):
            menu.addAction("Export Selected", self.export_selected)
        elif artifact['r_file_recovered']:
            menu.addAction("Export File", lambda: self.export_single_file(artifact))
        if artifact.get('r_file_is_directory', False):
            menu.addAction("Browse Folder", lambda: self.browse_folder(artifact))
        
        # Add selection actions
        menu.addSeparator()
        menu.addAction("Select All", self.select_all)
        menu.addAction("Deselect All", self.deselect_all)
        
        # Show menu
        menu.exec(QCursor.pos())
    
    def select_all(self):
        """Select all displayed artifacts."""
        if self.current_view_mode == "list":
            self.list_view.selectAll()
        else:
            # Get currently displayed artifacts
            displayed_artifacts = self.get_displayed_artifacts()
            
            # Select all displayed artifacts
            self.selected_artifacts = displayed_artifacts.copy()
            
            # Update view to reflect selections
            self.update_file_view(displayed_artifacts)
        
        self.update_selection_count()
    
    def deselect_all(self):
        """Deselect all artifacts."""
        if self.current_view_mode == "list":
            self.list_view.clearSelection()
        else:
            self.selected_artifacts = []
            self.update_file_view(self.get_displayed_artifacts())
        self.update_selection_count()
    
    def update_selection_count(self):
        """Update the selection count button text."""
        count = len(self.selected_artifacts) if self.selected_artifacts else 0
        recoverable_count = len([a for a in self.selected_artifacts if a.get('r_file_recovered')]) if self.selected_artifacts else 0
        if hasattr(self, 'selection_count_btn'):
            self.selection_count_btn.setText(f"📋 {count} Selected ({recoverable_count} recoverable)")
        self.update_persistent_status()
        
        # Enable/disable export selected based on recoverable selection
        if hasattr(self, 'export_action'):
            self.export_action.setEnabled(recoverable_count > 0)
    
    def show_selection_manager(self):
        """Show dialog to manage selected files."""
        if not self.selected_artifacts:
            QMessageBox.information(self, "Selection Manager", "No files selected.\n\nUse checkboxes or 'Select All' to select files.")
            return
        
        dialog = SelectionManagerDialog(self, self.selected_artifacts)
        dialog.selection_changed.connect(self.on_selection_manager_changed)
        dialog.exec()
    
    def on_selection_manager_changed(self, updated_selection):
        """Handle selection changes from the selection manager."""
        self.selected_artifacts = updated_selection
        self.update_selection_count()
        self.update_file_view(self.get_displayed_artifacts())
    
    def get_displayed_artifacts(self):
        """Get the currently displayed artifacts based on filters."""
        # This method should return the artifacts currently being displayed
        if hasattr(self, 'current_displayed_artifacts') and self.current_displayed_artifacts is not None:
            return self.current_displayed_artifacts
        return self.artifacts
    
    def export_tree_files(self, artifacts):
        """Export files from a tree node."""
        # Filter recoverable artifacts
        recoverable = [a for a in artifacts if a['r_file_recovered']]
        
        if not recoverable:
            QMessageBox.information(self, "Export", "No recoverable files in this selection.")
            return
        
        # Show export dialog
        self.show_export_dialog(recoverable)
    
    def export_selected(self):
        """Export selected files."""
        if not self.selected_artifacts:
            QMessageBox.information(self, "Export", "No files selected for export.")
            return
        
        # Filter recoverable artifacts
        recoverable = [a for a in self.selected_artifacts if a['r_file_recovered']]
        
        if not recoverable:
            QMessageBox.information(self, "Export", "None of the selected files are recoverable.")
            return
        
        # Show export dialog
        self.show_export_dialog(recoverable)
    
    def export_full_recycle_bin(self):
        """Export all recoverable files from the Recycle Bin."""
        if not self.artifacts:
            QMessageBox.information(self, "Export", "No artifacts loaded.")
            return
        
        # Filter all recoverable artifacts
        recoverable = [a for a in self.artifacts if a['r_file_recovered']]
        
        if not recoverable:
            QMessageBox.information(self, "Export", "No recoverable files found in the Recycle Bin.")
            return
        
        # Show export dialog with all recoverable files
        self.show_export_dialog(recoverable)
    
    def export_single_file(self, artifact):
        """Export a single file."""
        if not artifact['r_file_recovered']:
            QMessageBox.information(self, "Export", "This file is not recoverable.")
            return
        
        # Get file name from original path
        file_name = os.path.basename(artifact['original_path'])
        
        # Show save dialog
        export_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export File",
            file_name,
            "All Files (*.*)"
        )
        
        if not export_path:
            return
        
        # Export file
        self.statusBar.showMessage(f"Exporting file: {file_name}...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        # Export in a separate thread
        threading.Thread(
            target=self.export_single_file_thread,
            args=(artifact, export_path),
            daemon=True
        ).start()
    
    def export_single_file_thread(self, artifact, export_path):
        """Thread function to export a single file."""
        try:
            # Export file
            success = self.parser.export_file(artifact, export_path)
            
            # Update UI safely
            QMetaObject.invokeMethod(self, "show_export_result", Qt.QueuedConnection,
                                   Q_ARG(bool, success), Q_ARG(str, export_path))
                
        except Exception as e:
            QMetaObject.invokeMethod(self, "show_export_error", Qt.QueuedConnection,
                                   Q_ARG(str, str(e)))
        finally:
            QMetaObject.invokeMethod(self.progress_bar, "setVisible", Qt.QueuedConnection,
                                   Q_ARG(bool, False))
    
    @Slot(bool, str)
    def show_export_result(self, success, export_path):
        """Show export result."""
        if success:
            self.statusBar.showMessage(f"File exported successfully to: {export_path}")
            QMessageBox.information(self, "Export Complete", f"File exported successfully to:\n{export_path}")
        else:
            self.statusBar.showMessage("Failed to export file.")
            QMessageBox.warning(self, "Export Failed", "Failed to export file.")
    
    @Slot(str)
    def show_export_error(self, error_message):
        """Show export error."""
        self.statusBar.showMessage(f"Error exporting file: {error_message}")
        QMessageBox.critical(self, "Export Error", f"Error exporting file: {error_message}")
    
    def show_export_dialog(self, artifacts):
        """Show dialog for export options."""
        # Create dialog
        dialog = ExportDialog(self, artifacts, self.parser)
        dialog.export_started.connect(self.on_export_started)
        dialog.exec()
    
    def on_export_started(self, artifacts, export_dir, hash_types, generate_csv, preserve_structure,
                         sid_hierarchy, flat_export, both_hierarchies, overwrite_mode):
        """Handle export operation start."""
        # Update UI
        self.statusBar.showMessage(f"Exporting {len(artifacts)} files...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        # Create and show progress dialog
        self.export_progress_dialog = ExportProgressDialog(self, len(artifacts))
        self.export_progress_dialog.cancel_requested.connect(self.on_export_cancel_requested)
        self.export_progress_dialog.show()
        
        # Configure export worker
        self.export_worker.configure(
            artifacts, export_dir, hash_types, generate_csv, preserve_structure,
            sid_hierarchy, flat_export, both_hierarchies, overwrite_mode
        )
        
        # Start export
        self.export_worker.start()
    
    def on_export_cancel_requested(self):
        """Handle export cancel request from progress dialog."""
        if self.export_worker:
            self.export_worker.cancel()
    
    def on_export_progress(self, progress, message, eta):
        """Handle export progress updates with ETA."""
        self.progress_bar.setValue(progress)
        self.statusBar.showMessage(f"{message} | {eta}")
        
        # Update progress dialog if open
        if hasattr(self, 'export_progress_dialog') and self.export_progress_dialog:
            self.export_progress_dialog.update_progress(progress, message, eta)
    
    def on_export_complete(self, results):
        """Handle export completion."""
        # Close progress dialog
        if hasattr(self, 'export_progress_dialog') and self.export_progress_dialog:
            self.export_progress_dialog.export_complete()
            self.export_progress_dialog = None
        
        # Update UI
        self.progress_bar.setVisible(False)
        
        # Show results
        if results['cancelled']:
            message = "Export was cancelled by user."
        else:
            export_folder = results.get('export_folder', 'N/A')
            csv_file = os.path.basename(results['csv_path']) if results.get('csv_path') else None
            json_file = os.path.basename(results['json_path']) if results.get('json_path') else None
            error_csv_file = os.path.basename(results['error_csv_path']) if results.get('error_csv_path') else None
            
            message = (
                f"Export complete!\n\n"
                f"📁 Files exported to:\n{export_folder}\n\n"
                f"✓ Exported: {results['exported']} files\n"
                f"✗ Failed: {results['failed']} files\n"
                f"⚠ Skipped: {results['skipped']} files\n"
            )
            
            if csv_file:
                message += f"\n📄 CSV: {csv_file}"
            if json_file:
                message += f"\n📋 JSON: {json_file}"
            if error_csv_file:
                message += f"\n⚠ Errors: {error_csv_file}"
        
        QMessageBox.information(self, "Export Complete", message)
        
        # Update status
        if not results['cancelled']:
            self.statusBar.showMessage(f"Export complete. Exported {results['exported']} files.")
        else:
            self.statusBar.showMessage("Export cancelled.")
    
    def generate_report(self):
        """Generate a CSV report of all artifacts."""
        if not self.artifacts:
            QMessageBox.information(self, "Report", "No artifacts to include in report.")
            return
        
        # Show report options dialog
        dialog = ReportOptionsDialog(self)
        if dialog.exec() != QDialog.Accepted:
            return
        
        hash_types = dialog.get_selected_hash_types()
        include_recursive = dialog.get_include_recursive()
        
        # Show save dialog
        report_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Report",
            "recycle_bin_artifacts.csv",
            "CSV Files (*.csv);;All Files (*.*)"
        )
        
        if not report_path:
            return
        
        # Generate report using worker thread
        self.report_worker = ReportGenerationWorker(self.parser, self.artifacts, report_path, 
                                                   hash_types, include_recursive, 
                                                   timezone=self.current_timezone)
        self.report_worker.progress_update.connect(self.on_export_progress)
        self.report_worker.report_complete.connect(self.on_report_complete)
        self.report_worker.start()
        
        # Show progress
        self.statusBar.showMessage("Generating report...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
    
    @Slot(dict)
    def on_report_complete(self, result):
        """Handle report generation completion."""
        self.progress_bar.setVisible(False)
        
        if result['success']:
            QMessageBox.information(self, "Report", f"Report generated successfully at:\n{result['path']}")
            self.statusBar.showMessage(f"Report generated: {result['path']}")
        else:
            QMessageBox.critical(self, "Report Error", f"Error generating report: {result['error']}")
            self.statusBar.showMessage("Report generation failed.")
    
    def show_statistics(self):
        """Show statistics dialog."""
        if not self.parser:
            return
        
        dialog = StatisticsDialog(self, self.parser)
        dialog.exec()

class FileDetailsDialog(QDialog):
    """Dialog for displaying file details."""
    
    def __init__(self, parent, artifact, parser, timezone_str="UTC"):
        super().__init__(parent)
        self.artifact = artifact
        self.parser = parser
        self.hash_results = {}
        self.timezone_str = timezone_str
        self.is_dark_mode = bool(getattr(parent, "is_dark_mode", False))
        
        # Set dialog properties
        self.setWindowTitle("File Details")
        self.setMinimumSize(600, 500)
        self.resize(700, 600)
        
        # Create layout
        layout = QVBoxLayout(self)
        
        # Create header
        header_layout = QHBoxLayout()
        
        # File icon
        file_ext = artifact.get('file_ext', '').lower()
        icon = QIcon.fromTheme("text-x-generic", QApplication.style().standardIcon(QStyle.SP_FileIcon))
        
        if file_ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']:
            icon = QIcon.fromTheme("image-x-generic", QApplication.style().standardIcon(QStyle.SP_FileDialogDetailedView))
        elif file_ext in ['.doc', '.docx', '.pdf', '.txt']:
            icon = QIcon.fromTheme("text-x-generic", QApplication.style().standardIcon(QStyle.SP_FileDialogDetailedView))
        elif file_ext in ['.mp3', '.wav', '.ogg']:
            icon = QIcon.fromTheme("audio-x-generic", QApplication.style().standardIcon(QStyle.SP_MediaVolume))
        elif file_ext in ['.mp4', '.avi', '.mov']:
            icon = QIcon.fromTheme("video-x-generic", QApplication.style().standardIcon(QStyle.SP_MediaPlay))
        
        icon_label = QLabel()
        icon_label.setPixmap(icon.pixmap(32, 32))
        header_layout.addWidget(icon_label)
        
        # File name
        file_name = os.path.basename(artifact['original_path'])
        name_label = QLabel(file_name)
        name_label.setFont(QFont("Segoe UI", 12, QFont.Bold))
        header_layout.addWidget(name_label)
        header_layout.addStretch()
        
        layout.addLayout(header_layout)
        
        # Create tabs
        tabs = QTabWidget()
        
        # General tab
        general_tab = QWidget()
        general_layout = QFormLayout(general_tab)
        
        # Original path
        path_label = QLabel(artifact['original_path'])
        path_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        path_label.setWordWrap(True)
        general_layout.addRow("Original Path:", path_label)
        
        # File size
        size_bytes = artifact['original_size']
        size_formatted = self.format_file_size(size_bytes)
        size_label = QLabel(f"{size_formatted} ({size_bytes:,} bytes)")
        size_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        general_layout.addRow("File Size:", size_label)
        
        # File type
        file_type = artifact.get('file_type', 'Unknown')
        type_label = QLabel(file_type)
        type_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        general_layout.addRow("File Type:", type_label)
        
        # Deletion time with timezone
        if artifact.get('deletion_time'):
            date_text = self.format_datetime_with_tz(artifact['deletion_time'])
        else:
            date_text = "Unknown"
        date_label = QLabel(date_text)
        date_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        general_layout.addRow(f"Deletion Time ({self.timezone_str}):", date_label)
        
        # Add timestamp fields with timezone
        for time_field, label_text in [
            ('created_time', 'Creation Time'),
            ('modified_time', 'Modification Time'),
            ('accessed_time', 'Access Time'),
            ('r_file_created_time', 'R File Creation Time'),
            ('r_file_modified_time', 'R File Modification Time'),
            ('r_file_accessed_time', 'R File Access Time')
        ]:
            if artifact.get(time_field):
                time_text = self.format_datetime_with_tz(artifact[time_field])
                time_label = QLabel(time_text)
                time_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
                general_layout.addRow(f"{label_text} ({self.timezone_str}):", time_label)
        
        # Recovery status
        if artifact['r_file_recovered']:
            status_label = QLabel("Recoverable")
            status_label.setStyleSheet("color: green; font-weight: bold;")
        else:
            status_label = QLabel("Not recoverable")
            status_label.setStyleSheet("color: red; font-weight: bold;")
        general_layout.addRow("Recovery Status:", status_label)
        
        tabs.addTab(general_tab, "General")
        
        # Technical tab
        tech_tab = QWidget()
        tech_layout = QFormLayout(tech_tab)
        
        # SID
        sid_label = QLabel(artifact['sid'])
        sid_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        tech_layout.addRow("SID:", sid_label)
        
        # $I file - show base name with child path in brackets if present
        i_file_name = artifact['i_file_name']
        # Extract base $I name and child path
        if '_child_' in i_file_name:
            parts = i_file_name.split('_child_', 1)
            i_display = f"{parts[0]} ({parts[1]})" if len(parts) > 1 else i_file_name
        else:
            i_display = i_file_name
        i_file_label = QLabel(i_display)
        i_file_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        tech_layout.addRow("$I File:", i_file_label)
        
        # $R file - show base name with child path in brackets if present
        r_file_name = artifact['r_file_name']
        # Extract base $R name and child path
        if '_child_' in r_file_name:
            parts = r_file_name.split('_child_', 1)
            r_display = f"{parts[0]} ({parts[1]})" if len(parts) > 1 else r_file_name
        else:
            r_display = r_file_name
        r_file_label = QLabel(r_display)
        r_file_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        tech_layout.addRow("$R File:", r_file_label)
        
        # Version
        version_str = "Unknown"
        if artifact['version'] == 1:
            version_str = "Windows Vista/7/8/8.1"
        elif artifact['version'] == 2:
            version_str = "Windows 10/11"
        version_label = QLabel(f"{version_str} (Version {artifact['version']})")
        version_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        tech_layout.addRow("Windows Version:", version_label)
        
        # Hash calculation
        hash_group = QGroupBox("File Hashes")
        hash_layout = QVBoxLayout(hash_group)
        
        hash_button_layout = QHBoxLayout()
        md5_check = QCheckBox("MD5")
        md5_check.setChecked(True)
        hash_button_layout.addWidget(md5_check)
        
        sha1_check = QCheckBox("SHA-1")
        hash_button_layout.addWidget(sha1_check)
        
        sha256_check = QCheckBox("SHA-256")
        hash_button_layout.addWidget(sha256_check)
        
        calculate_button = QPushButton("Calculate Hashes")
        calculate_button.clicked.connect(lambda: self.calculate_hashes(
            [h for h, c in [('md5', md5_check), ('sha1', sha1_check), ('sha256', sha256_check)] if c.isChecked()]
        ))
        hash_button_layout.addWidget(calculate_button)
        hash_layout.addLayout(hash_button_layout)
        
        # Hash results
        self.hash_text = QTextEdit()
        self.hash_text.setReadOnly(True)
        self.hash_text.setMaximumHeight(100)
        hash_layout.addWidget(self.hash_text)
        
        tech_layout.addRow(hash_group)
        tabs.addTab(tech_tab, "Technical")
        
        # Preview tab (if file is recoverable)
        if artifact['r_file_recovered'] and not artifact.get('r_file_is_directory', False):
            preview_tab = QWidget()
            preview_layout = QVBoxLayout(preview_tab)
            
            if file_ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']:
                # Image preview
                preview_layout.addWidget(QLabel("Image Preview:"))
                load_button = QPushButton("Load Image Preview")
                load_button.clicked.connect(self.load_image_preview)
                preview_layout.addWidget(load_button, 0, Qt.AlignLeft)
                
                self.image_label = QLabel()
                self.image_label.setAlignment(Qt.AlignCenter)
                self.image_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
                preview_layout.addWidget(self.image_label)
            else:
                # Hex preview for other files
                preview_layout.addWidget(QLabel("File Preview (Hex):"))
                load_button = QPushButton("Load File Preview")
                load_button.clicked.connect(self.load_hex_preview)
                preview_layout.addWidget(load_button, 0, Qt.AlignLeft)
                
                # Create horizontal layout for offset, hex, and ASCII columns
                hex_container = QHBoxLayout()
                hex_container.setSpacing(0)
                
                # Offset column (narrow, non-selectable)
                self.offset_text = QTextEdit()
                self.offset_text.setReadOnly(True)
                self.offset_text.setFont(QFont("Courier New", 10))
                self.offset_text.setMaximumWidth(90)
                self.offset_text.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
                hex_container.addWidget(self.offset_text)
                
                # Hex column
                self.hex_text = QTextEdit()
                self.hex_text.setReadOnly(True)
                self.hex_text.setFont(QFont("Courier New", 10))
                self.hex_text.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
                hex_container.addWidget(self.hex_text, 2)
                
                # ASCII column
                self.ascii_text = QTextEdit()
                self.ascii_text.setReadOnly(True)
                self.ascii_text.setFont(QFont("Courier New", 10))
                hex_container.addWidget(self.ascii_text, 1)

                # Theme-aware styling for hex view
                if self.is_dark_mode:
                    offset_style = (
                        "background-color: #0b1220; color: #e5e7eb; "
                        "border: 1px solid #334155; border-right: none;"
                    )
                    hex_style = (
                        "background-color: #0f172a; color: #e5e7eb; "
                        "border: 1px solid #334155; border-left: none; border-right: none;"
                    )
                    ascii_style = (
                        "background-color: #0b1220; color: #e5e7eb; "
                        "border: 1px solid #334155; border-left: none;"
                    )
                else:
                    offset_style = (
                        "background-color: #f0f0f0; color: #666666; "
                        "border: 1px solid #ccc; border-right: none;"
                    )
                    hex_style = (
                        "background-color: #ffffff; color: #1e293b; "
                        "border: 1px solid #ccc; border-left: none; border-right: none;"
                    )
                    ascii_style = (
                        "background-color: #f8f8f8; color: #1e293b; "
                        "border: 1px solid #ccc; border-left: none;"
                    )

                self.offset_text.setStyleSheet(offset_style)
                self.hex_text.setStyleSheet(hex_style)
                self.ascii_text.setStyleSheet(ascii_style)
                
                # Sync scrolling between all three columns
                def sync_scroll(value):
                    self.offset_text.verticalScrollBar().setValue(value)
                    self.hex_text.verticalScrollBar().setValue(value)
                    self.ascii_text.verticalScrollBar().setValue(value)
                
                self.offset_text.verticalScrollBar().valueChanged.connect(sync_scroll)
                self.hex_text.verticalScrollBar().valueChanged.connect(sync_scroll)
                self.ascii_text.verticalScrollBar().valueChanged.connect(sync_scroll)
                
                preview_layout.addLayout(hex_container)
            
            tabs.addTab(preview_tab, "Preview")
        
        layout.addWidget(tabs)
        
        # Create button box
        button_box = QHBoxLayout()
        
        if artifact['r_file_recovered']:
            export_button = QPushButton("Export File")
            export_button.clicked.connect(self.export_file)
            button_box.addWidget(export_button)
        
        if artifact.get('r_file_is_directory', False):
            browse_button = QPushButton("Browse Folder")
            browse_button.clicked.connect(self.browse_folder)
            button_box.addWidget(browse_button)
        
        button_box.addStretch()
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.accept)
        button_box.addWidget(close_button)
        
        layout.addLayout(button_box)
    
    def format_file_size(self, size):
        """Format file size in human-readable form."""
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size/1024:.1f} KB"
        elif size < 1024 * 1024 * 1024:
            return f"{size/(1024*1024):.1f} MB"
        else:
            return f"{size/(1024*1024*1024):.1f} GB"
    
    def format_datetime_with_tz(self, dt):
        """Format datetime with timezone conversion."""
        if dt is None:
            return "Unknown"
        try:
            from zoneinfo import ZoneInfo
            if self.timezone_str and self.timezone_str != "UTC":
                # Convert to target timezone
                if dt.tzinfo is None:
                    # Assume UTC if no timezone info
                    dt = dt.replace(tzinfo=ZoneInfo("UTC"))
                target_tz = ZoneInfo(self.timezone_str)
                dt = dt.astimezone(target_tz)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return dt.strftime("%Y-%m-%d %H:%M:%S")
    
    def calculate_hashes(self, hash_types):
        """Calculate file hashes."""
        if not self.artifact['r_file_recovered']:
            self.hash_text.setText("File is not recoverable. Cannot calculate hashes.")
            return
        
        if not hash_types:
            self.hash_text.setText("Please select at least one hash algorithm.")
            return
        
        # Show calculating message
        self.hash_text.setText("Calculating hashes...")
        
        # Calculate hashes in a separate thread
        self.hash_thread = HashCalculationThread(self.parser, self.artifact, hash_types)
        self.hash_thread.hash_calculated.connect(self.on_hash_calculated)
        self.hash_thread.start()
    
    def on_hash_calculated(self, hash_results):
        """Handle hash calculation completion."""
        if hash_results:
            hash_text = ""
            for hash_type, hash_value in hash_results.items():
                hash_text += f"{hash_type.upper()}: {hash_value}\n"
            self.hash_text.setText(hash_text)
        else:
            self.hash_text.setText("Error calculating hashes.")
    
    def load_image_preview(self):
        """Load and display image preview."""
        self.image_label.setText("Loading image preview...")
        
        # Load preview in a separate thread
        self.preview_thread = ImagePreviewThread(self.parser, self.artifact)
        self.preview_thread.image_loaded.connect(self.on_image_loaded)
        self.preview_thread.start()
    
    def on_image_loaded(self, pixmap):
        """Handle image preview loaded."""
        if pixmap and not pixmap.isNull():
            # Resize to fit
            max_width = self.image_label.width() - 20
            max_height = self.image_label.height() - 20
            if pixmap.width() > max_width or pixmap.height() > max_height:
                pixmap = pixmap.scaled(max_width, max_height, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            
            self.image_label.setPixmap(pixmap)
        else:
            self.image_label.setText("Failed to load image preview.")
    
    def load_hex_preview(self):
        """Load and display hex preview."""
        self.offset_text.setText("")
        self.hex_text.setText("Loading file preview...")
        self.ascii_text.setText("")
        
        # Load preview in a separate thread
        self.hex_thread = HexPreviewThread(self.parser, self.artifact)
        self.hex_thread.hex_loaded.connect(self.on_hex_loaded)
        self.hex_thread.start()
    
    def on_hex_loaded(self, offset_col, hex_col, ascii_col):
        """Handle hex preview loaded."""
        if hex_col:
            self.offset_text.setText(offset_col)
            self.hex_text.setText(hex_col)
            self.ascii_text.setText(ascii_col)
        else:
            self.offset_text.setText("")
            self.hex_text.setText("Failed to load file preview.")
            self.ascii_text.setText("")
    
    def export_file(self):
        """Export the file."""
        # Get file name from original path
        file_name = os.path.basename(self.artifact['original_path'])
        
        # Show save dialog
        export_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export File",
            file_name,
            "All Files (*.*)"
        )
        
        if not export_path:
            return
        
        # Export file
        try:
            success = self.parser.export_file(self.artifact, export_path)
            if success:
                QMessageBox.information(self, "Export Complete", f"File exported successfully to:\n{export_path}")
            else:
                QMessageBox.warning(self, "Export Failed", "Failed to export file.")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Error exporting file: {str(e)}")
    
    def browse_folder(self):
        """Browse folder contents."""
        # Close this dialog and signal parent to browse folder
        self.accept()
        if hasattr(self.parent(), 'browse_folder'):
            self.parent().browse_folder(self.artifact)

class HashCalculationThread(QThread):
    """Thread for calculating hashes without blocking UI."""
    hash_calculated = Signal(dict)
    
    def __init__(self, parser, artifact, hash_types):
        super().__init__()
        self.parser = parser
        self.artifact = artifact
        self.hash_types = hash_types
    
    def run(self):
        """Calculate hashes."""
        try:
            hash_results = self.parser.calculate_file_hash(self.artifact['r_file_addr'], self.hash_types)
            self.hash_calculated.emit(hash_results)
        except Exception as e:
            logger.error(f"Error calculating hashes: {str(e)}")
            self.hash_calculated.emit({})

class ImagePreviewThread(QThread):
    """Thread for loading image previews without blocking UI."""
    image_loaded = Signal(QPixmap)
    
    def __init__(self, parser, artifact):
        super().__init__()
        self.parser = parser
        self.artifact = artifact
    
    def run(self):
        """Load image preview."""
        try:
            # Get file preview
            preview_data = self.parser.get_file_preview(self.artifact)
            if not preview_data:
                self.image_loaded.emit(QPixmap())
                return
            
            # Create QImage from data
            image = QImage.fromData(preview_data)
            if image.isNull():
                self.image_loaded.emit(QPixmap())
                return
            
            # Create pixmap
            pixmap = QPixmap.fromImage(image)
            self.image_loaded.emit(pixmap)
            
        except Exception as e:
            logger.error(f"Error loading image preview: {str(e)}")
            self.image_loaded.emit(QPixmap())

class HexPreviewThread(QThread):
    """Thread for loading hex previews without blocking UI."""
    hex_loaded = Signal(str, str, str)  # offset, hex, ascii
    
    def __init__(self, parser, artifact):
        super().__init__()
        self.parser = parser
        self.artifact = artifact
    
    def run(self):
        """Load hex preview."""
        try:
            # Get file preview (limit to 4KB)
            preview_data = self.parser.get_file_preview(self.artifact, max_size=4096)
            if not preview_data:
                self.hex_loaded.emit("", "", "")
                return
            
            # Format as separate columns
            offset_col = ""
            hex_col = ""
            ascii_col = ""
            
            offset = 0
            while offset < len(preview_data):
                # Get 16 bytes
                chunk = preview_data[offset:offset+16]
                
                # Format offset
                offset_col += f"{offset:08x}\n"
                
                # Format hex
                hex_str = " ".join(f"{b:02x}" for b in chunk)
                hex_str = hex_str.ljust(49)  # Pad to consistent width
                hex_col += f"{hex_str}\n"
                
                # Format ASCII
                ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                ascii_col += f"|{ascii_str}|\n"
                
                offset += 16
            
            self.hex_loaded.emit(offset_col, hex_col, ascii_col)
            
        except Exception as e:
            logger.error(f"Error loading hex preview: {str(e)}")
            self.hex_loaded.emit("", "", "")

class ExportDialog(QDialog):
    """Dialog for export options."""
    export_started = Signal(list, str, list, bool, bool, bool, bool, bool, str)
    
    def __init__(self, parent, artifacts, parser):
        super().__init__(parent)
        self.artifacts = artifacts
        self.parser = parser
        
        # Set dialog properties
        self.setWindowTitle("Export Files")
        self.setMinimumSize(500, 450)
        
        # Create layout
        layout = QVBoxLayout(self)
        
        # Create header
        header_label = QLabel("Export Files")
        header_label.setFont(QFont("Segoe UI", 12, QFont.Bold))
        layout.addWidget(header_label)
        
        # File count
        count_label = QLabel(f"Exporting {len(artifacts)} files")
        layout.addWidget(count_label)
        
        # Destination section
        dest_group = QGroupBox("Destination")
        dest_layout = QVBoxLayout(dest_group)
        
        dest_layout_row = QHBoxLayout()
        self.dest_edit = QLineEdit()
        self.dest_edit.setReadOnly(True)
        dest_layout_row.addWidget(self.dest_edit)
        
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_destination)
        dest_layout_row.addWidget(browse_button)
        dest_layout.addLayout(dest_layout_row)
        layout.addWidget(dest_group)
        
        # Organization options
        org_group = QGroupBox("Organization Options")
        org_layout = QVBoxLayout(org_group)
        
        # Create radio button group
        self.org_button_group = QButtonGroup()
        
        self.flat_radio = QRadioButton("Flat export (all files in one folder)")
        self.flat_radio.setChecked(True)
        self.org_button_group.addButton(self.flat_radio)
        org_layout.addWidget(self.flat_radio)
        
        self.preserve_radio = QRadioButton("Preserve original folder structure only")
        self.org_button_group.addButton(self.preserve_radio)
        org_layout.addWidget(self.preserve_radio)
        
        self.sid_radio = QRadioButton("Preserve SID hierarchy only")
        self.org_button_group.addButton(self.sid_radio)
        org_layout.addWidget(self.sid_radio)
        
        self.both_radio = QRadioButton("Preserve both SID and folder structure")
        self.org_button_group.addButton(self.both_radio)
        org_layout.addWidget(self.both_radio)
        
        layout.addWidget(org_group)
        
        # Hash options
        hash_group = QGroupBox("Hash Options")
        hash_layout = QVBoxLayout(hash_group)
        
        self.md5_check = QCheckBox("Calculate MD5 hash")
        hash_layout.addWidget(self.md5_check)
        
        self.sha1_check = QCheckBox("Calculate SHA-1 hash")
        hash_layout.addWidget(self.sha1_check)
        
        self.sha256_check = QCheckBox("Calculate SHA-256 hash")
        hash_layout.addWidget(self.sha256_check)
        
        layout.addWidget(hash_group)
        
        # Report options
        report_group = QGroupBox("Report Options")
        report_layout = QVBoxLayout(report_group)
        
        self.csv_check = QCheckBox("Generate CSV report")
        self.csv_check.setChecked(True)
        report_layout.addWidget(self.csv_check)
        
        self.json_check = QCheckBox("Generate JSON report")
        self.json_check.setChecked(True)
        report_layout.addWidget(self.json_check)
        
        # Note about file conflicts
        conflict_note = QLabel("Note: Duplicate filenames will automatically get a suffix (e.g., file_1.txt)")
        conflict_note.setStyleSheet("color: #6c757d; font-style: italic; font-size: 11px;")
        conflict_note.setWordWrap(True)
        report_layout.addWidget(conflict_note)
        
        layout.addWidget(report_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)
        
        self.export_button = QPushButton("Export")
        self.export_button.setDefault(True)
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self.start_export)
        button_layout.addWidget(self.export_button)
        
        layout.addLayout(button_layout)
    
    def browse_destination(self):
        """Browse for export destination."""
        export_dir = QFileDialog.getExistingDirectory(
            self,
            "Select Export Directory",
            ""
        )
        
        if export_dir:
            self.dest_edit.setText(export_dir)
            self.export_button.setEnabled(True)
    
    def start_export(self):
        """Start the export operation."""
        # Check if destination is selected
        export_dir = self.dest_edit.text()
        if not export_dir:
            QMessageBox.warning(self, "Export", "Please select an export directory.")
            return
        
        # Get selected hash types
        hash_types = []
        if self.md5_check.isChecked():
            hash_types.append("md5")
        if self.sha1_check.isChecked():
            hash_types.append("sha1")
        if self.sha256_check.isChecked():
            hash_types.append("sha256")
        
        # Always use suffix for conflicts (removed conflict options)
        overwrite_mode = "never"
        
        # Get organization options
        flat_export = self.flat_radio.isChecked()
        preserve_structure = self.preserve_radio.isChecked()
        sid_hierarchy = self.sid_radio.isChecked()
        both_hierarchies = self.both_radio.isChecked()
        
        # Start export
        self.export_started.emit(
            self.artifacts,
            export_dir,
            hash_types,
            self.csv_check.isChecked(),
            preserve_structure,
            sid_hierarchy,
            flat_export,
            both_hierarchies,
            overwrite_mode
        )
        
        # Close dialog
        self.accept()

class ExportProgressDialog(QDialog):
    """Dialog for showing export progress with queue display."""
    cancel_requested = Signal()
    
    def __init__(self, parent, total_files):
        super().__init__(parent)
        self.total_files = total_files
        self.start_time = time.time()
        
        self.setWindowTitle("Exporting Files")
        self.setMinimumSize(500, 300)
        self.setModal(True)
        
        layout = QVBoxLayout(self)
        
        # Header
        header_label = QLabel(f"Exporting {total_files} files...")
        header_label.setFont(QFont("Segoe UI", 12, QFont.Bold))
        layout.addWidget(header_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #cbd5e1;
                border-radius: 6px;
                background-color: #f1f5f9;
                text-align: center;
                min-height: 24px;
            }
            QProgressBar::chunk {
                background-color: #3b82f6;
                border-radius: 5px;
            }
        """)
        layout.addWidget(self.progress_bar)
        
        # Current file label
        self.current_file_label = QLabel("Preparing...")
        self.current_file_label.setStyleSheet("color: #64748b;")
        self.current_file_label.setWordWrap(True)
        layout.addWidget(self.current_file_label)
        
        # Stats grid
        stats_widget = QWidget()
        stats_layout = QGridLayout(stats_widget)
        stats_layout.setContentsMargins(0, 10, 0, 10)
        
        # Files processed
        stats_layout.addWidget(QLabel("Files processed:"), 0, 0)
        self.files_label = QLabel("0 / " + str(total_files))
        self.files_label.setStyleSheet("font-weight: bold;")
        stats_layout.addWidget(self.files_label, 0, 1)
        
        # Time elapsed
        stats_layout.addWidget(QLabel("Time elapsed:"), 1, 0)
        self.elapsed_label = QLabel("0s")
        self.elapsed_label.setStyleSheet("font-weight: bold;")
        stats_layout.addWidget(self.elapsed_label, 1, 1)
        
        # ETA
        stats_layout.addWidget(QLabel("Estimated remaining:"), 2, 0)
        self.eta_label = QLabel("Calculating...")
        self.eta_label.setStyleSheet("font-weight: bold; color: #3b82f6;")
        stats_layout.addWidget(self.eta_label, 2, 1)
        
        # Queue remaining
        stats_layout.addWidget(QLabel("Queue remaining:"), 3, 0)
        self.queue_label = QLabel(str(total_files) + " files")
        self.queue_label.setStyleSheet("font-weight: bold;")
        stats_layout.addWidget(self.queue_label, 3, 1)
        
        layout.addWidget(stats_widget)
        
        # Spacer
        layout.addStretch()
        
        # Cancel button
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        self.cancel_btn = QPushButton("Cancel Export")
        self.cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: #ef4444;
                color: white;
                border: none;
                padding: 10px 24px;
                border-radius: 6px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #dc2626;
            }
        """)
        self.cancel_btn.clicked.connect(self.on_cancel_clicked)
        button_layout.addWidget(self.cancel_btn)
        
        layout.addLayout(button_layout)
        
        # Timer for elapsed time updates
        self.elapsed_timer = QTimer(self)
        self.elapsed_timer.timeout.connect(self.update_elapsed_time)
        self.elapsed_timer.start(1000)  # Update every second
    
    def update_progress(self, progress, message, eta):
        """Update the progress display."""
        self.progress_bar.setValue(progress)
        self.current_file_label.setText(message)
        self.eta_label.setText(eta)
        
        # Parse files count from message if possible
        if "[" in message and "/" in message:
            try:
                parts = message.split("]")[0].replace("[", "").split("/")
                current = int(parts[0])
                total = int(parts[1])
                self.files_label.setText(f"{current} / {total}")
                self.queue_label.setText(f"{total - current} files")
            except:
                pass
    
    def update_elapsed_time(self):
        """Update the elapsed time display."""
        elapsed = int(time.time() - self.start_time)
        if elapsed < 60:
            self.elapsed_label.setText(f"{elapsed}s")
        elif elapsed < 3600:
            mins = elapsed // 60
            secs = elapsed % 60
            self.elapsed_label.setText(f"{mins}m {secs}s")
        else:
            hours = elapsed // 3600
            mins = (elapsed % 3600) // 60
            self.elapsed_label.setText(f"{hours}h {mins}m")
    
    def on_cancel_clicked(self):
        """Handle cancel button click."""
        reply = QMessageBox.question(
            self, "Cancel Export",
            "Are you sure you want to cancel the export?\n\nFiles already exported will be kept.",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.cancel_btn.setText("Cancelling...")
            self.cancel_btn.setEnabled(False)
            self.cancel_requested.emit()
    
    def export_complete(self):
        """Handle export completion."""
        self.elapsed_timer.stop()
        self.close()
    
    def closeEvent(self, event):
        """Handle dialog close."""
        self.elapsed_timer.stop()
        super().closeEvent(event)


class SelectionManagerDialog(QDialog):
    """Dialog for managing selected files."""
    selection_changed = Signal(list)
    
    def __init__(self, parent, selected_artifacts):
        super().__init__(parent)
        self.selected_artifacts = list(selected_artifacts)  # Make a copy
        
        self.setWindowTitle("Selection Manager")
        self.setMinimumSize(700, 500)
        self.resize(800, 600)
        
        layout = QVBoxLayout(self)
        
        # Header with count
        header_layout = QHBoxLayout()
        header_label = QLabel(f"Managing {len(self.selected_artifacts)} Selected Files")
        header_label.setFont(QFont("Segoe UI", 12, QFont.Bold))
        header_layout.addWidget(header_label)
        
        # Recoverable count
        recoverable = len([a for a in self.selected_artifacts if a.get('r_file_recovered')])
        recoverable_label = QLabel(f"({recoverable} recoverable)")
        recoverable_label.setStyleSheet("color: #10b981; font-weight: bold;")
        header_layout.addWidget(recoverable_label)
        header_layout.addStretch()
        layout.addLayout(header_layout)
        
        # Create table for selected files
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["File Name", "Type", "Original Path", "Size", "Deleted", "Status"])
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.ExtendedSelection)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)  # Original Path column
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)  # Disable editing
        self.table.setWordWrap(False)  # Disable word wrap for cleaner display
        self.table.verticalHeader().setDefaultSectionSize(28)  # Fixed row height
        
        self.populate_table()
        layout.addWidget(self.table)
        
        # Button row
        button_layout = QHBoxLayout()
        
        remove_btn = QPushButton("Remove Selected")
        remove_btn.setStyleSheet("""
            QPushButton {
                background-color: #ef4444;
                color: white;
                border: none;
                padding: 10px 18px;
                border-radius: 6px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #dc2626;
            }
        """)
        remove_btn.clicked.connect(self.remove_selected)
        button_layout.addWidget(remove_btn)
        
        clear_all_btn = QPushButton("Clear All")
        clear_all_btn.setStyleSheet("""
            QPushButton {
                background-color: #6b7280;
                color: white;
                border: none;
                padding: 10px 18px;
                border-radius: 6px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #4b5563;
            }
        """)
        clear_all_btn.clicked.connect(self.clear_all)
        button_layout.addWidget(clear_all_btn)
        
        button_layout.addStretch()
        
        done_btn = QPushButton("Done")
        done_btn.setStyleSheet("""
            QPushButton {
                background-color: #3b82f6;
                color: white;
                border: none;
                padding: 10px 24px;
                border-radius: 6px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #2563eb;
            }
        """)
        done_btn.clicked.connect(self.accept)
        button_layout.addWidget(done_btn)
        
        layout.addLayout(button_layout)
    
    def populate_table(self):
        """Populate the table with selected artifacts."""
        self.table.setRowCount(len(self.selected_artifacts))
        
        for i, artifact in enumerate(self.selected_artifacts):
            # File name
            file_name = os.path.basename(artifact['original_path'])
            name_item = QTableWidgetItem(file_name)
            name_item.setData(Qt.UserRole, i)  # Store index
            self.table.setItem(i, 0, name_item)
            
            # Type (Folder or File)
            is_folder = artifact.get('r_file_is_directory', False)
            type_item = QTableWidgetItem("📁 Folder" if is_folder else "📄 File")
            if is_folder:
                type_item.setForeground(QColor("#f59e0b"))  # Orange for folders
            else:
                type_item.setForeground(QColor("#3b82f6"))  # Blue for files
            self.table.setItem(i, 1, type_item)
            
            # Original path
            path_item = QTableWidgetItem(artifact['original_path'])
            self.table.setItem(i, 2, path_item)
            
            # Size
            size = artifact.get('original_size', 0)
            if size < 1024:
                size_text = f"{size} B"
            elif size < 1024 * 1024:
                size_text = f"{size/1024:.1f} KB"
            else:
                size_text = f"{size/(1024*1024):.1f} MB"
            size_item = QTableWidgetItem(size_text)
            self.table.setItem(i, 3, size_item)
            
            # Deletion time
            if artifact.get('deletion_time'):
                date_text = artifact['deletion_time'].strftime('%Y-%m-%d %H:%M')
            else:
                date_text = "Unknown"
            date_item = QTableWidgetItem(date_text)
            self.table.setItem(i, 4, date_item)
            
            # Status
            if artifact.get('r_file_recovered'):
                status_item = QTableWidgetItem("Recoverable")
                status_item.setForeground(QColor("#10b981"))
            else:
                status_item = QTableWidgetItem("Not recoverable")
                status_item.setForeground(QColor("#ef4444"))
            self.table.setItem(i, 5, status_item)
        
        self.table.resizeColumnsToContents()
    
    def remove_selected(self):
        """Remove selected rows from the selection."""
        selected_rows = set()
        for item in self.table.selectedItems():
            selected_rows.add(item.row())
        
        if not selected_rows:
            QMessageBox.information(self, "Remove", "Please select rows to remove.")
            return
        
        # Remove from the end to avoid index shifting
        for row in sorted(selected_rows, reverse=True):
            if 0 <= row < len(self.selected_artifacts):
                del self.selected_artifacts[row]
        
        # Repopulate table
        self.populate_table()
        
        # Emit signal
        self.selection_changed.emit(self.selected_artifacts)
        
        # Update header
        recoverable = len([a for a in self.selected_artifacts if a.get('r_file_recovered')])
        self.findChild(QLabel).setText(f"Managing {len(self.selected_artifacts)} Selected Files")
    
    def clear_all(self):
        """Clear all selections."""
        reply = QMessageBox.question(
            self, "Clear All",
            "Are you sure you want to clear all selections?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.selected_artifacts = []
            self.populate_table()
            self.selection_changed.emit(self.selected_artifacts)
            self.accept()


class ReportOptionsDialog(QDialog):
    """Dialog for report generation options."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("Report Options")
        self.setMinimumSize(350, 250)
        
        layout = QVBoxLayout(self)
        
        # Header
        header_label = QLabel("Select report options:")
        header_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        layout.addWidget(header_label)
        
        # Hash options
        hash_group = QGroupBox("Hash Algorithms")
        hash_layout = QVBoxLayout(hash_group)
        
        self.md5_check = QCheckBox("MD5")
        hash_layout.addWidget(self.md5_check)
        
        self.sha1_check = QCheckBox("SHA-1")
        hash_layout.addWidget(self.sha1_check)
        
        self.sha256_check = QCheckBox("SHA-256")
        hash_layout.addWidget(self.sha256_check)
        
        layout.addWidget(hash_group)
        
        # Recursive options
        recursive_group = QGroupBox("Folder Content Options")
        recursive_layout = QVBoxLayout(recursive_group)
        
        self.recursive_check = QCheckBox("Include recursive folder contents in report")
        self.recursive_check.setToolTip("When enabled, files within deleted folders will be listed as separate entries")
        recursive_layout.addWidget(self.recursive_check)
        
        layout.addWidget(recursive_group)
        
        # Note
        note_label = QLabel("Note: Hash calculation and recursive scanning may take time for large datasets.")
        note_label.setStyleSheet("color: #6c757d; font-style: italic; font-size: 11px;")
        note_label.setWordWrap(True)
        layout.addWidget(note_label)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)
        
        ok_button = QPushButton("Generate Report")
        ok_button.setDefault(True)
        ok_button.clicked.connect(self.accept)
        button_layout.addWidget(ok_button)
        
        layout.addLayout(button_layout)
    
    def get_selected_hash_types(self):
        """Get selected hash types."""
        hash_types = []
        if self.md5_check.isChecked():
            hash_types.append("md5")
        if self.sha1_check.isChecked():
            hash_types.append("sha1")
        if self.sha256_check.isChecked():
            hash_types.append("sha256")
        return hash_types
    
    def get_include_recursive(self):
        """Get recursive option."""
        return self.recursive_check.isChecked()

class StatisticsDialog(QDialog):
    """Dialog for displaying statistics."""
    
    def __init__(self, parent, parser):
        super().__init__(parent)
        self.parser = parser
        
        # Set dialog properties
        self.setWindowTitle("Statistics")
        self.setMinimumSize(500, 400)
        
        # Create layout
        layout = QVBoxLayout(self)
        
        # Header
        header_label = QLabel("Recycle Bin Analysis Statistics")
        header_label.setFont(QFont("Segoe UI", 14, QFont.Bold))
        header_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(header_label)
        
        # Get statistics
        stats = parser.get_statistics()
        
        # Create tabs
        tabs = QTabWidget()
        
        # General statistics tab
        general_tab = QWidget()
        general_layout = QFormLayout(general_tab)
        
        # Image information
        general_layout.addRow("Image File:", QLabel(os.path.basename(parser.image_path)))
        general_layout.addRow("Partitions Found:", QLabel(str(stats['partitions_found'])))
        general_layout.addRow("SID Directories:", QLabel(str(stats['sid_dirs_found'])))
        
        # File statistics
        general_layout.addRow("$I Files Found:", QLabel(str(stats['i_files_found'])))
        general_layout.addRow("$I Files Parsed:", QLabel(str(stats['i_files_parsed'])))
        general_layout.addRow("$R Files Found:", QLabel(str(stats['r_files_found'])))
        
        # Recovery statistics
        general_layout.addRow("Recoverable Files:", QLabel(str(stats['recoverable_files'])))
        general_layout.addRow("Unrecoverable Files:", QLabel(str(stats['unrecoverable_files'])))
        
        # Timing
        if stats.get('duration'):
            general_layout.addRow("Processing Time:", QLabel(f"{stats['duration']:.2f} seconds"))
        
        tabs.addTab(general_tab, "General")
        
        # File types tab
        types_tab = QWidget()
        types_layout = QVBoxLayout(types_tab)
        
        types_table = QTableWidget()
        types_table.setColumnCount(2)
        types_table.setHorizontalHeaderLabels(["File Type", "Count"])
        
        file_types = stats.get('file_types', {})
        types_table.setRowCount(len(file_types))
        
        for i, (file_type, count) in enumerate(file_types.items()):
            types_table.setItem(i, 0, QTableWidgetItem(file_type))
            types_table.setItem(i, 1, QTableWidgetItem(str(count)))
        
        types_table.resizeColumnsToContents()
        types_layout.addWidget(types_table)
        
        tabs.addTab(types_tab, "File Types")
        
        layout.addWidget(tabs)
        
        # Close button
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.accept)
        layout.addWidget(close_button, 0, Qt.AlignCenter)

def main():
    """Main function."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Recycle Bin Forensic Explorer")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--log", help="Log file path")
    args = parser.parse_args()

    # Set up logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    setup_logging(log_file=args.log, file_level=log_level, console_level=log_level)

    # Create application
    app = QApplication(sys.argv)

    # Set application style
    app.setStyle(QStyleFactory.create("Fusion"))
    
    # Set tooltip palette at app level for reliable visibility across themes
    palette = app.palette()
    palette.setColor(QPalette.ToolTipBase, QColor(26, 26, 46))  # Dark blue-gray #1a1a2e
    palette.setColor(QPalette.ToolTipText, QColor(240, 240, 240))  # Near-white #f0f0f0
    app.setPalette(palette)
    
    # Force tooltip stylesheet at app level
    app.setStyleSheet("""
        QToolTip {
            background-color: #1a1a2e;
            color: #f0f0f0;
            border: 1px solid #4a4a6a;
            border-radius: 6px;
            padding: 8px 12px;
            font-size: 12px;
            font-family: 'Segoe UI', sans-serif;
        }
    """)

    # Create main window
    window = MainWindow()
    window.show()

    # Run application
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
