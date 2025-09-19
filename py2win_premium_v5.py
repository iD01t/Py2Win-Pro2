#!/usr/bin/env python4
"""
Py2Win Premium v5.0.0 - Enterprise Python to Windows Executable Builder
Production-grade GUI application for packaging Python projects into Windows executables and installers.

Copyright 2025 - Built with security, reliability, and user experience in mind.
"""

import sys
import os
import json
import ast
import shutil
import zipfile
import urllib.request
import time
import threading
import queue
import subprocess
import logging
import tempfile
import hashlib
import configparser
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Callable, Any, Tuple
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from concurrent.futures import ThreadPoolExecutor
# Cryptography Fernet: provide typing hint for static checkers and a safe runtime import
# cryptography.Fernet availability: try import, otherwise provide a runtime stub and HAVE_FERNET flag
HAVE_FERNET = False
try:
    import importlib
    _mod = importlib.import_module('cryptography.fernet')
    Fernet = getattr(_mod, 'Fernet')
    HAVE_FERNET = True
except Exception:
    HAVE_FERNET = False
    # Provide a small stub so references to Fernet don't break runtime parsing
    class Fernet:  # type: ignore
        @staticmethod
        def generate_key() -> bytes:
            return b""

        def __init__(self, key: bytes):
            pass

        def encrypt(self, data: bytes) -> bytes:  # pragma: no cover - stub
            raise RuntimeError("cryptography.Fernet not available")

        def decrypt(self, token: bytes) -> bytes:  # pragma: no cover - stub
            raise RuntimeError("cryptography.Fernet not available")

try:
    import customtkinter as ctk
except ImportError:
    print("Installing required dependencies...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "customtkinter"])
    import customtkinter as ctk

# Windows-specific modules
win32crypt = None
if sys.platform == 'win32':
    try:
        import win32crypt  # type: ignore
    except ImportError:
        try:
            print("Installing pywin32 for Windows DPAPI support...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "pywin32>=306"])
            import win32crypt  # type: ignore
        except (subprocess.CalledProcessError, ImportError) as e:
            print(f"Warning: Could not install/import pywin32: {e}")
            # Continue without win32crypt - secure storage will fall back to file-based encryption

# Constants
APP_NAME = "Py2Win Premium"
APP_VERSION = "5.0.0"
CONFIG_DIR = Path.home() / ".py2win"
TOOLS_DIR = CONFIG_DIR / "tools"
NSIS_DIR = TOOLS_DIR / "nsis"
BUILD_ENV_DIR = CONFIG_DIR / "build_env"
LOGS_DIR = Path(os.environ.get('APPDATA', CONFIG_DIR)) / "Py2Win" / "logs"
CACHE_DIR = CONFIG_DIR / "cache"

# URLs and checksums for tool downloads
NSIS_URL = "https://prdownloads.sourceforge.net/nsis/nsis-3.09.zip"
NSIS_CHECKSUM = "1bb9fc85ee5b220d3869325dbb9d191dfe6537070f641c30fbb275c97051fd0c"
NSIS_MIRRORS = [
    "https://sourceforge.net/projects/nsis/files/NSIS%203/3.09/nsis-3.09.zip/download",
    "https://github.com/NSIS/nsis/releases/download/v3.09/nsis-3.09.zip"
]

REQUIRED_PACKAGES = ["pyinstaller", "wheel", "setuptools", "requests", "pillow", "tomli"]
OPTIONAL_PACKAGES = ["nuitka", "upx"]

# Ensure directories exist
for dir_path in [CONFIG_DIR, TOOLS_DIR, LOGS_DIR, CACHE_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)

# Modern color scheme
COLORS = {
    'primary': '#2563eb',
    'primary_hover': '#1d4ed8',
    'secondary': '#64748b', 
    'success': '#10b981',
    'warning': '#f59e0b',
    'error': '#ef4444',
    'surface': '#1e293b',
    'surface_light': '#334155',
    'text': '#f8fafc',
    'text_secondary': '#cbd5e1'
}

@dataclass
class BuildConfig:
    """Configuration for building executables"""
    script_path: str = ""
    exe_name: str = ""
    output_dir: str = "./dist"
    one_file: bool = True
    windowed: bool = True
    clean_build: bool = True
    icon_path: str = ""
    hidden_imports: List[str] = field(default_factory=list)
    exclude_modules: List[str] = field(default_factory=list)
    data_paths: List[Tuple[str, str]] = field(default_factory=list)  # (source, target)
    use_upx: bool = False
    backend: str = "pyinstaller"  # "pyinstaller" or "nuitka"
    version: str = "1.0.0"
    company: str = ""
    description: str = ""
    copyright: str = ""

@dataclass
class InstallerConfig:
    """Configuration for NSIS installer"""
    app_name: str = ""
    version: str = "1.0.0"
    company: str = ""
    description: str = ""
    output_dir: str = "./installers"
    desktop_shortcut: bool = True
    start_menu: bool = True
    install_dir: str = ""  # Empty means auto-detect
    per_user: bool = False
    eula_file: Optional[str] = None
    banner_image: Optional[str] = None
    silent_mode: bool = False

@dataclass
class SigningConfig:
    """Configuration for code signing"""
    tool_path: str = ""
    cert_path: str = ""
    cert_password: str = ""  # Will be encrypted when stored
    timestamp_server: str = "http://timestamp.digicert.com"
    use_credential_manager: bool = True

@dataclass
class ProjectInfo:
    """Project information and metadata"""
    name: str = ""
    version: str = "1.0.0"
    author: str = ""
    description: str = ""
    license: str = "MIT"

@dataclass
class AdvancedConfig:
    """Advanced build configuration options"""
    optimization_level: int = 1
    debug_mode: bool = False
    console_mode: bool = True
    upx_compression: bool = False
    exclude_modules: List[str] = field(default_factory=list)
    include_modules: List[str] = field(default_factory=list)
    custom_args: List[str] = field(default_factory=list)

@dataclass
class ProjectConfig:
    """Complete project configuration with build profiles"""
    project: ProjectInfo = field(default_factory=ProjectInfo)
    build_profiles: Dict[str, BuildConfig] = field(default_factory=dict)
    active_profile: str = "default"
    advanced: AdvancedConfig = field(default_factory=AdvancedConfig)
    installer: InstallerConfig = field(default_factory=InstallerConfig)
    signing: Optional[SigningConfig] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ProjectConfig':
        """Create ProjectConfig from dictionary"""
        config = cls()
        if not data:
            return config
            
        if 'project' in data:
            config.project = ProjectInfo(**data['project'])
        if 'build_profiles' in data:
            config.build_profiles = {
                name: BuildConfig(**profile)
                for name, profile in data['build_profiles'].items()
            }
        if 'active_profile' in data:
            config.active_profile = data['active_profile']
        if 'advanced' in data:
            config.advanced = AdvancedConfig(**data['advanced'])
        if 'installer' in data:
            config.installer = InstallerConfig(**data['installer'])
        if 'signing' in data:
            config.signing = SigningConfig(**data['signing'])
        if 'metadata' in data:
            config.metadata = data['metadata']
            
        return config
    
    def __post_init__(self):
        """Initialize with default profile if none exists"""
        if not self.build_profiles:
            self.build_profiles["default"] = BuildConfig()
    
    @property
    def build(self) -> BuildConfig:
        """Get the active build configuration"""
        return self.build_profiles.get(self.active_profile, self.build_profiles.get("default", BuildConfig()))
    
    @build.setter
    def build(self, value: BuildConfig):
        """Set the active build configuration"""
        self.build_profiles[self.active_profile] = value
    
    def add_profile(self, name: str, config: Optional[BuildConfig] = None) -> bool:
        """Add a new build profile"""
        if name in self.build_profiles:
            return False
        self.build_profiles[name] = config or BuildConfig()
        return True
    
    def remove_profile(self, name: str) -> bool:
        """Remove a build profile"""
        if name == "default" or name not in self.build_profiles:
            return False
        del self.build_profiles[name]
        if self.active_profile == name:
            self.active_profile = "default"
        return True
    
    def switch_profile(self, name: str) -> bool:
        """Switch to a different build profile"""
        if name not in self.build_profiles:
            return False
        self.active_profile = name
        return True

class SecureStorage:
    """Secure storage for sensitive data using Windows DPAPI or fallback encryption"""
    
    def __init__(self):
        self._available = win32crypt is not None
    
    def get_password(self, key: str) -> Optional[str]:
        """Retrieve password securely (alias for backward compatibility)"""
        return self.retrieve_password(key)

    def store_password(self, key: str, password: str) -> bool:
        """Store password securely using Windows DPAPI"""
        if not password:
            return False
            
        if not self._available:
            return self._store_password_fallback(key, password)
            
        try:
            if win32crypt is None:  # Type checking helper
                return False
                
            encrypted_data = win32crypt.CryptProtectData(
                password.encode('utf-8'),
                f"Py2Win {key}",
                None, None, None, 0
            )
            
            storage_file = CONFIG_DIR / f"{key}.dat"
            with open(storage_file, 'wb') as f:
                f.write(encrypted_data)
            return True
        except Exception as e:
            logging.warning(f"Failed to store password using DPAPI: {e}")
            return self._store_password_fallback(key, password)
    
    def retrieve_password(self, key: str) -> Optional[str]:
        """Retrieve password using Windows DPAPI"""
        if not self._available:
            return self._retrieve_password_fallback(key)
            
        try:
            if win32crypt is None:  # Type checking helper
                return None
                
            storage_file = CONFIG_DIR / f"{key}.dat"
            if not storage_file.exists():
                return None
                
            with open(storage_file, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = win32crypt.CryptUnprotectData(encrypted_data, None, None, None, 0)
            return decrypted_data[1].decode('utf-8')
        except Exception as e:
            logging.warning(f"Failed to retrieve password using DPAPI: {e}")
            return self._retrieve_password_fallback(key)
            
    def _store_password_fallback(self, key: str, password: str) -> bool:
        """Fallback storage using basic encryption when DPAPI is unavailable"""
        if not HAVE_FERNET:
            return False
            
        try:
            key_file = CONFIG_DIR / ".keyfile"
            if not key_file.exists():
                fernet_key = Fernet.generate_key()
                with open(key_file, 'wb') as f:
                    f.write(fernet_key)
            else:
                with open(key_file, 'rb') as f:
                    fernet_key = f.read()
                    
            f = Fernet(fernet_key)
            encrypted = f.encrypt(password.encode('utf-8'))
            storage_file = CONFIG_DIR / f"{key}.enc"
            with open(storage_file, 'wb') as f:
                f.write(encrypted)
            return True
        except Exception as e:
            logging.error(f"Failed to store password using fallback encryption: {e}")
            return False
            
    def _retrieve_password_fallback(self, key: str) -> Optional[str]:
        """Fallback retrieval using basic encryption when DPAPI is unavailable"""
        if not HAVE_FERNET:
            return None
            
        try:
            key_file = CONFIG_DIR / ".keyfile"
            if not key_file.exists():
                return None
                
            with open(key_file, 'rb') as f:
                fernet_key = f.read()
                
            storage_file = CONFIG_DIR / f"{key}.enc"
            if not storage_file.exists():
                return None
                
            with open(storage_file, 'rb') as f:
                encrypted = f.read()
                
            f = Fernet(fernet_key)
            decrypted = f.decrypt(encrypted)
            return decrypted.decode('utf-8')
        except Exception as e:
            logging.error(f"Failed to retrieve password using fallback encryption: {e}")
            return None

class RotatingLogger:
    """Thread-safe rotating logger with GUI integration"""
    
    def __init__(self, max_size_mb: int = 10, max_files: int = 5):
        self.max_size = max_size_mb * 1024 * 1024
        self.max_files = max_files
        self.log_queue = queue.Queue()
        self.setup_logger()
    
    @property
    def log(self):
        """Property to access logger directly"""
        return self.logger

    def setup_logger(self):
        """Setup rotating file and GUI logger"""
        self.logger = logging.getLogger('Py2Win')
        self.logger.setLevel(logging.INFO)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # File handler with rotation
        log_file = LOGS_DIR / f"py2win_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        
        formatter = logging.Formatter(
            '[%(asctime)s] %(levelname)-8s [%(threadName)-12s] %(message)s',
            '%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s', '%H:%M:%S')
        console_handler.setFormatter(console_formatter)
        
        # Queue handler for GUI
        queue_handler = logging.Handler()
        def _emit_to_queue(record):
            try:
                msg = console_formatter.format(record)
                # Ensure string messages only
                if not isinstance(msg, str):
                    msg = str(msg)
                self.log_queue.put(msg)
            except Exception:
                pass
        queue_handler.emit = _emit_to_queue
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        self.logger.addHandler(queue_handler)
        
        # Rotate old logs
        self._rotate_logs()
    
    def _rotate_logs(self):
        """Rotate old log files"""
        try:
            log_files = sorted(LOGS_DIR.glob("py2win_*.log"))
            
            # Remove excess files
            if len(log_files) > self.max_files:
                for old_file in log_files[:-self.max_files]:
                    old_file.unlink()
            
            # Check current file size
            current_log = LOGS_DIR / f"py2win_{datetime.now().strftime('%Y%m%d')}.log"
            if current_log.exists() and current_log.stat().st_size > self.max_size:
                # Archive current log
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                archived = LOGS_DIR / f"py2win_{timestamp}.log"
                current_log.rename(archived)
        except Exception:
            pass  # Don't fail startup on log rotation issues
    
    def info(self, msg: str, *args):
        self.logger.info(self._redact_secrets(msg), *args)
    
    def warning(self, msg: str, *args):
        self.logger.warning(self._redact_secrets(msg), *args)
    
    def error(self, msg: str, *args):
        self.logger.error(self._redact_secrets(msg), *args)
    
    def debug(self, msg: str, *args):
        self.logger.debug(self._redact_secrets(msg), *args)
    
    def _redact_secrets(self, message: str) -> str:
        """Redact potential secrets from log messages"""
        import re
        # Redact common patterns
        patterns = [
            (r'--password\s+\S+', '--password ***'),
            (r'/p\s+\S+', '/p ***'),
            (r'password["\']?\s*[:=]\s*["\']?[^"\'\s]+', 'password=***'),
            (r'token["\']?\s*[:=]\s*["\']?[^"\'\s]+', 'token=***'),
            (r'key["\']?\s*[:=]\s*["\']?[^"\'\s]+', 'key=***'),
        ]
        
        result = message
        for pattern, replacement in patterns:
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
        return result

    # Backwards-compatibility: make RotatingLogger callable and proxy attributes
    def __call__(self, *args, **kwargs):
        """Allow calling the logger like a function (proxy to info)."""
        try:
            if args:
                self.info(str(args[0]), *args[1:], **kwargs)
        except Exception:
            pass

    def __getattr__(self, item):
        # Forward unknown attributes to internal logger if present
        if '_logger' in self.__dict__ and hasattr(self.__dict__['_logger'], item):
            return getattr(self.__dict__['_logger'], item)
        if hasattr(self, 'logger') and hasattr(self.logger, item):
            return getattr(self.logger, item)
        raise AttributeError(item)

class ChecksumValidator:
    """Validates file checksums and handles retries"""
    
    @staticmethod
    def verify_file(file_path: Path, expected_hash: str, algorithm: str = 'sha256') -> bool:
        """Verify file checksum"""
        try:
            hash_obj = hashlib.new(algorithm)
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest().lower() == expected_hash.lower()
        except Exception:
            return False
    
    @staticmethod
    def download_with_verification(url: str, file_path: Path, expected_hash: str, 
                                 mirrors: Optional[List[str]] = None,
                                 progress_callback: Optional[Callable[[str], Any]] = None) -> bool:
        """Download file with checksum verification and mirror fallback"""
        urls_to_try = [url] + (mirrors or [])
        
        for _, download_url in enumerate(urls_to_try):
            try:
                # Download with progress
                response = urllib.request.urlopen(download_url, timeout=30)
                total_size = int(response.headers.get('Content-Length', 0))
                
                with open(file_path, 'wb') as f:
                    downloaded = 0
                    while True:
                        chunk = response.read(8192)
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded += len(chunk)
                        
                        if progress_callback and total_size > 0:
                            progress = (downloaded / total_size) * 100
                            progress_callback(f"Downloading... {progress:.1f}%")
                
                # Verify checksum
                if ChecksumValidator.verify_file(file_path, expected_hash):
                    if progress_callback:
                        progress_callback("Download completed and verified")
                    return True
                else:
                    file_path.unlink()  # Remove invalid file
                    if progress_callback:
                        progress_callback(f"Checksum mismatch for {download_url}")
            
            except Exception as e:
                if file_path.exists():
                    file_path.unlink()
                if progress_callback:
                    progress_callback(f"Download failed from {download_url}: {str(e)}")
        
        return False

class DependencyAnalyzer:
    """Advanced dependency analysis and conflict resolution"""
    
    def __init__(self, python_exe: str):
        self.python_exe = python_exe
        self.pip_exe = self._find_pip()
        self.logger = RotatingLogger()
    
    def _find_pip(self) -> str:
        """Find pip executable"""
        pip_path = Path(self.python_exe).parent / "Scripts" / "pip.exe"
        if pip_path.exists():
            return str(pip_path)
        return "pip"
    
    def full_diagnosis(self, script_path: Optional[str] = None) -> Dict[str, Any]:
        """Comprehensive dependency analysis"""
        results = {
            'python_version': self._check_python_version(),
            'pip_check': self._run_pip_check(),
            'missing_packages': self._check_missing_packages(),
            'outdated_packages': self._check_outdated_packages(),
            'wheel_issues': self._check_wheel_issues(),
            'conflicts': self._analyze_conflicts(),
            'recommendations': []
        }
        
        # Generate recommendations
        recommendations = []
        if not results['python_version']['supported']:
            recommendations.append("Upgrade Python to version 3.8 or newer")
        
        if results['missing_packages']:
            recommendations.append(f"Install missing packages: {', '.join(results['missing_packages'])}")
        
        if results['conflicts']:
            recommendations.append("Resolve version conflicts using pip-tools or manual pins")
        
        results['recommendations'] = recommendations
        return results
    
    def _check_python_version(self) -> Dict[str, Any]:
        """Check Python version compatibility"""
        version = sys.version_info
        supported = version >= (3, 8)
        return {
            'version': f"{version.major}.{version.minor}.{version.micro}",
            'supported': supported,
            'path': self.python_exe
        }
    
    def _run_pip_check(self) -> Dict[str, Any]:
        """Run pip check for dependency issues"""
        try:
            result = subprocess.run(
                [self.pip_exe, "check"], 
                capture_output=True, text=True, timeout=30
            )
            return {
                'success': result.returncode == 0,
                'output': result.stdout + result.stderr,
                'issues': [] if result.returncode == 0 else result.stderr.splitlines()
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'output': 'Timeout during pip check', 'issues': ['Timeout']}
        except Exception as e:
            return {'success': False, 'output': str(e), 'issues': [str(e)]}
    
    def _check_missing_packages(self) -> List[str]:
        """Check for missing required packages"""
        try:
            result = subprocess.run(
                [self.pip_exe, "list", "--format=freeze"], 
                capture_output=True, text=True, timeout=30
            )
            installed = {pkg.split('==')[0].lower() for pkg in result.stdout.splitlines()}
            return [pkg for pkg in REQUIRED_PACKAGES if pkg.lower() not in installed]
        except Exception:
            return REQUIRED_PACKAGES  # Assume all missing on error
    
    def _check_outdated_packages(self) -> List[Dict[str, str]]:
        """Check for outdated packages"""
        try:
            result = subprocess.run(
                [self.pip_exe, "list", "--outdated", "--format=json"], 
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                return json.loads(result.stdout)
        except Exception:
            pass
        return []
    
    def _check_wheel_issues(self) -> List[str]:
        """Check for packages that might need wheel builds"""
        # Simplified implementation - would be more comprehensive in production
        problematic_packages = []
        try:
            result = subprocess.run(
                [self.pip_exe, "list", "--format=json"], 
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                packages = json.loads(result.stdout)
                # Check for packages known to have wheel issues
                wheel_problematic = ['lxml', 'numpy', 'scipy', 'pillow']
                for pkg in packages:
                    if pkg['name'].lower() in wheel_problematic:
                        problematic_packages.append(pkg['name'])
        except Exception:
            pass
        return problematic_packages
    
    def _analyze_conflicts(self) -> List[Dict[str, str]]:
        """Analyze version conflicts"""
        conflicts = []
        pip_check = self._run_pip_check()
        if not pip_check['success'] and pip_check['issues']:
            for issue in pip_check['issues']:
                if 'has requirement' in issue or 'incompatible' in issue:
                    conflicts.append({'description': issue, 'severity': 'high'})
        return conflicts
    
    def install_packages(self, packages: List[str], progress_callback: Optional[Callable[[str], Any]] = None) -> bool:
        """Install packages with progress tracking"""
        try:
            cmd = [self.pip_exe, "install", "--upgrade"] + packages
            self.logger.info(f"Installing packages: {' '.join(packages)}")
            
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT,
                text=True, bufsize=1, universal_newlines=True
            )
            
            out = process.stdout or []
            for line in out:
                line = line.strip()
                if line:
                    self.logger.info(line)
                    if progress_callback:
                        progress_callback(line)
            
            process.wait()
            success = process.returncode == 0
            
            if success:
                self.logger.info("Package installation completed successfully")
            else:
                self.logger.error(f"Package installation failed with code: {process.returncode}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Package installation error: {str(e)}")
            return False

    def get_dependencies(self, script_path: str, include_runtime: bool = True) -> List[str]:
        """Detect dependencies for a script using HiddenImportDetector and return a flat list"""
        try:
            detector = HiddenImportDetector()
            detected = detector.detect_imports(script_path, include_runtime=include_runtime)
            deps = list(set(detected.get('static', []) + detected.get('dynamic', [])))
            return deps
        except Exception as e:
            self.logger.error(f"Failed to get dependencies: {e}")
            return []

class HiddenImportDetector:
    """Advanced hidden import detection with AST and runtime analysis"""
    
    def __init__(self):
        self.logger = RotatingLogger()
        self.stdlib_modules = self._get_stdlib_modules()
    
    def _get_stdlib_modules(self) -> set:
        """Get comprehensive list of standard library modules"""
        stdlib_modules = {
            # Core modules
            'sys', 'os', 'json', 'time', 'datetime', 'pathlib', 'subprocess',
            'threading', 'queue', 'logging', 'tempfile', 'shutil', 'urllib',
            'zipfile', 'ast', 'dataclasses', 'typing', 'tkinter', 'collections',
            'itertools', 'functools', 'operator', 'copy', 'pickle', 'base64',
            'hashlib', 'hmac', 'secrets', 'uuid', 'random', 'math', 'decimal',
            'fractions', 'statistics', 'array', 'struct', 'codecs', 'io',
            're', 'string', 'textwrap', 'unicodedata', 'stringprep',
            # Network and internet
            'socket', 'ssl', 'http', 'ftplib', 'poplib', 'imaplib', 'smtplib',
            'telnetlib', 'urllib', 'email', 'mailbox', 'csv', 'xml',
            # File formats and compression
            'gzip', 'bz2', 'lzma', 'tarfile', 'configparser', 'fileinput',
            # OS interface
            'glob', 'fnmatch', 'platform', 'stat', 'filecmp', 'tempfile',
            # Concurrency
            'multiprocessing', 'concurrent', 'asyncio', 'selectors',
            # Development tools
            'unittest', 'doctest', 'pdb', 'profile', 'timeit', 'trace',
            'warnings', 'importlib', 'pkgutil', 'modulefinder', 'runpy',
        }
        return stdlib_modules
    
    def detect_imports(self, script_path: str, include_runtime: bool = True) -> Dict[str, List[str]]:
        """Detect hidden imports using multiple strategies"""
        if not Path(script_path).exists():
            return {'static': [], 'dynamic': [], 'suggestions': []}
        
        results = {
            'static': [],
            'dynamic': [],
            'suggestions': []
        }
        
        try:
            # Static analysis
            static_imports = self._static_analysis(script_path)
            results['static'] = static_imports
            
            # Dynamic analysis (if enabled)
            if include_runtime:
                dynamic_imports = self._dynamic_analysis(script_path)
                results['dynamic'] = dynamic_imports
            
            # Generate suggestions based on common patterns
            all_imports = list(set(static_imports + results['dynamic']))
            suggestions = self._generate_suggestions(all_imports)
            results['suggestions'] = suggestions
            
            self.logger.info(f"Detected {len(all_imports)} potential hidden imports")
            
        except Exception as e:
            self.logger.error(f"Import detection failed: {str(e)}")
        
        return results

    def get_dependencies(self, script_path: str, include_runtime: bool = True) -> Dict[str, List[str]]:
        """Backward-compatible alias for detect_imports"""
        return self.detect_imports(script_path, include_runtime=include_runtime)
    
    def _static_analysis(self, script_path: str) -> List[str]:
        """Analyze imports using AST"""
        imports = set()
        
        try:
            with open(script_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                # Direct imports
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        module_name = alias.name.split('.')[0]
                        if module_name not in self.stdlib_modules:
                            imports.add(alias.name)
                
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        module_name = node.module.split('.')[0]
                        if module_name not in self.stdlib_modules:
                            imports.add(node.module)
                
                # Dynamic imports
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id == '__import__':
                        if node.args and isinstance(node.args[0], (ast.Str, ast.Constant)):
                            module_name = node.args[0].s if isinstance(node.args[0], ast.Str) else node.args[0].value
                            if isinstance(module_name, str):
                                root_module = module_name.split('.')[0]
                                if root_module not in self.stdlib_modules:
                                    imports.add(module_name)
        
        except Exception as e:
            self.logger.error(f"Static analysis failed: {str(e)}")
        
        return sorted(list(imports))
    
    def _dynamic_analysis(self, script_path: str) -> List[str]:
        """Enhanced dynamic analysis for runtime imports"""
        import re
        dynamic_imports = set()
        
        try:
            # Method 1: Use modulefinder for static dependency analysis
            try:
                from modulefinder import ModuleFinder
                finder = ModuleFinder()
                finder.run_script(script_path)
                
                for name, mod in finder.modules.items():
                    mod_file = getattr(mod, '__file__', None)
                    if mod_file and not self._is_stdlib(name):
                        dynamic_imports.add(name.split('.')[0])
            except:
                pass
            
            # Method 2: Parse for common dynamic import patterns
            with open(script_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Find __import__ calls
            import_pattern = r'__import__\s*\(\s*["\']([^"\']+)["\']\s*\)'
            for match in re.finditer(import_pattern, content):
                dynamic_imports.add(match.group(1))
            
            # Find importlib.import_module calls
            importlib_pattern = r'import_module\s*\(\s*["\']([^"\']+)["\']\s*\)'
            for match in re.finditer(importlib_pattern, content):
                dynamic_imports.add(match.group(1))
            
            # Method 3: Analyze common framework patterns
            framework_patterns = {
                'flask': ['flask', 'werkzeug', 'jinja2', 'click', 'itsdangerous'],
                'django': ['django', 'pytz', 'sqlparse'],
                'fastapi': ['fastapi', 'uvicorn', 'starlette', 'pydantic'],
                'numpy': ['numpy', 'numpy.core._multiarray_umath', 'numpy.core._dtype'],
                'pandas': ['pandas', 'numpy', 'dateutil', 'pytz'],
                'matplotlib': ['matplotlib', 'numpy', 'matplotlib.backends.backend_tkagg'],
                'scipy': ['scipy', 'numpy'],
                'sklearn': ['sklearn', 'numpy', 'scipy', 'joblib'],
                'pygame': ['pygame', 'numpy'],
                'tkinter': ['tkinter', '_tkinter'],
                'customtkinter': ['customtkinter', 'tkinter', 'PIL'],
                'requests': ['requests', 'urllib3', 'certifi', 'chardet', 'idna'],
                'PyQt5': ['PyQt5', 'PyQt5.QtCore', 'PyQt5.QtGui', 'PyQt5.QtWidgets'],
                'PySide2': ['PySide2', 'shiboken2'],
                'win32': ['win32api', 'win32con', 'win32com', 'pythoncom', 'pywintypes']
            }
            
            # Check for framework usage
            for framework, deps in framework_patterns.items():
                if framework in content or f"import {framework}" in content or f"from {framework}" in content:
                    dynamic_imports.update(deps)
            
            # Common runtime imports
            if any(x in content for x in ['__file__', 'pkg_resources', 'pkgutil']):
                dynamic_imports.update(['pkg_resources', 'setuptools', 'importlib_metadata'])
            
        except Exception as e:
            self.logger.warning(f"Dynamic analysis error: {e}")
            # Fallback to basic runtime imports
            dynamic_imports.update([
                'pkg_resources', 'importlib_metadata', 'setuptools',
                'distutils', 'numpy.random', 'matplotlib.backends'
            ])
        
        return sorted(list(dynamic_imports))
    
    def _is_stdlib(self, module_name: str) -> bool:
        """Check if a module is part of the standard library"""
        if module_name in self.stdlib_modules:
            return True
        if module_name in sys.builtin_module_names:
            return True
        stdlib_prefixes = ['_', 'encodings.', 'importlib.', 'collections.', 'urllib.']
        return any(module_name.startswith(prefix) for prefix in stdlib_prefixes)
    
    def _generate_suggestions(self, detected_imports: List[str]) -> List[str]:
        """Generate additional import suggestions based on patterns"""
        suggestions = []
        
        for imp in detected_imports:
            # Common package patterns
            if imp.startswith('matplotlib'):
                suggestions.extend(['matplotlib.backends.backend_tkagg', 'matplotlib.figure'])
            elif imp.startswith('numpy'):
                suggestions.extend(['numpy.random', 'numpy.linalg'])
            elif imp.startswith('PIL') or imp.startswith('Pillow'):
                suggestions.extend(['PIL.Image', 'PIL.ImageTk'])
            elif imp.startswith('requests'):
                suggestions.extend(['urllib3', 'chardet', 'certifi'])
            elif imp.startswith('tkinter'):
                suggestions.extend(['tkinter.ttk', 'tkinter.filedialog', 'tkinter.messagebox'])
        
        return list(set(suggestions) - set(detected_imports))

class BuildOrchestrator:
    """Advanced build orchestration with multiple backends"""
    
    def __init__(self):
        self.logger = RotatingLogger()
        self.executor = ThreadPoolExecutor(max_workers=2)
        self.current_process = None
        self.cancel_event = threading.Event()
    
    def build(self, config: BuildConfig, progress_callback: Optional[Callable[[str], Any]] = None) -> bool:
        """Build executable with specified backend"""
        if not config.script_path or not Path(config.script_path).exists():
            self.logger.error(f"Script path not found: {config.script_path}")
            return False
        
        self.cancel_event.clear()
        
        try:
            # Pre-build validation
            if not self._validate_build_config(config):
                return False
            
            # Extract version from project files if not specified
            if not config.version or config.version == "1.0.0":
                config.version = self._extract_version(config.script_path) or config.version
            
            # Clean previous builds if requested
            if config.clean_build:
                self._clean_build_dirs(config.output_dir)
            
            # Select build backend
            if config.backend.lower() == "nuitka":
                return self._build_with_nuitka(config, progress_callback)
            else:
                return self._build_with_pyinstaller(config, progress_callback)
                
        except Exception as e:
            self.logger.error(f"Build failed with exception: {str(e)}")
            return False
        finally:
            self.current_process = None
    
    def cancel_build(self):
        """Cancel current build operation"""
        self.cancel_event.set()
        if self.current_process:
            try:
                self.current_process.terminate()
                self.logger.info("Build process terminated")
            except Exception as e:
                self.logger.error(f"Error terminating build: {str(e)}")
    
    def _validate_build_config(self, config: BuildConfig) -> bool:
        """Validate build configuration"""
        script_path = Path(config.script_path)
        
        if not script_path.exists():
            self.logger.error("Script file does not exist")
            return False
        
        if not script_path.suffix.lower() in ['.py', '.pyw']:
            self.logger.error("Script must be a Python file (.py or .pyw)")
            return False
        
        if config.icon_path and not Path(config.icon_path).exists():
            self.logger.warning("Icon file not found, will skip icon")
            config.icon_path = ""
        
        # Validate data paths
        valid_data_paths = []
        for source, target in config.data_paths:
            if Path(source).exists():
                valid_data_paths.append((source, target))
            else:
                self.logger.warning(f"Data path not found: {source}")
        config.data_paths = valid_data_paths
        
        return True
    
    def _extract_version(self, script_path: str) -> Optional[str]:
        """Extract version from pyproject.toml, setup.cfg, or script"""
        script_dir = Path(script_path).parent
        
        # Try pyproject.toml
        pyproject_path = script_dir / "pyproject.toml"
        if pyproject_path.exists():
            try:
                import tomli  # type: ignore
                with open(pyproject_path, 'rb') as f:
                    pyproject = tomli.load(f)
                    return pyproject.get('project', {}).get('version')
            except ImportError:
                pass  # tomli not available
            except Exception:
                pass
        
        # Try setup.cfg
        setup_cfg = script_dir / "setup.cfg"
        if setup_cfg.exists():
            try:
                config = configparser.ConfigParser()
                config.read(setup_cfg)
                return config.get('metadata', 'version', fallback=None)
            except Exception:
                pass
        
        # Try to extract from script __version__
        try:
            with open(script_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            import re
            version_match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
            if version_match:
                return version_match.group(1)
        except Exception:
            pass
        
        return None
    
    def _clean_build_dirs(self, output_dir: str):
        """Clean build directories"""
        dirs_to_clean = [output_dir, "./build", "./__pycache__"]
        
        for dir_path in dirs_to_clean:
            if Path(dir_path).exists():
                try:
                    shutil.rmtree(dir_path)
                    self.logger.info(f"Cleaned directory: {dir_path}")
                except Exception as e:
                    self.logger.warning(f"Could not clean {dir_path}: {str(e)}")
    
    def _build_with_pyinstaller(self, config: BuildConfig, progress_callback: Optional[Callable[[str], Any]] = None) -> bool:
        """Build with PyInstaller"""
        try:
            # Create version file
            version_file = self._create_version_file(config)
            
            # Build PyInstaller command
            cmd = self._build_pyinstaller_command(config, version_file)
            
            # Execute build
            success = self._execute_build_command(cmd, progress_callback)
            
            # Cleanup version file
            if version_file and Path(version_file).exists():
                Path(version_file).unlink()
            
            return success
            
        except Exception as e:
            self.logger.error(f"PyInstaller build failed: {str(e)}")
            return False
    
    def _build_with_nuitka(self, config: BuildConfig, progress_callback: Optional[Callable[[str], Any]] = None) -> bool:
        """Build with Nuitka"""
        try:
            # Check if Nuitka is available
            result = subprocess.run([sys.executable, "-c", "import nuitka"], 
                                  capture_output=True, timeout=10)
            if result.returncode != 0:
                self.logger.error("Nuitka not available. Install with: pip install nuitka")
                return False
            
            # Build Nuitka command
            cmd = self._build_nuitka_command(config)
            
            # Execute build
            return self._execute_build_command(cmd, progress_callback)
            
        except Exception as e:
            self.logger.error(f"Nuitka build failed: {str(e)}")
            return False
    
    def _create_version_file(self, config: BuildConfig) -> Optional[str]:
        """Create version info file for executable"""
        try:
            version_parts = config.version.split('.')
            while len(version_parts) < 4:
                version_parts.append('0')
            
            version_tuple = ','.join(version_parts)
            
            version_content = f"""# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({version_tuple}),
    prodvers=({version_tuple}),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable('040904B0', [
        StringStruct('CompanyName', '{config.company or "Built with Py2Win Premium"}'),
        StringStruct('FileDescription', '{config.description or config.exe_name or "Python Application"}'),
        StringStruct('FileVersion', '{config.version}'),
        StringStruct('InternalName', '{config.exe_name or "app"}'),
        StringStruct('LegalCopyright', '{config.copyright or f"Copyright {datetime.now().year}"}'),
        StringStruct('OriginalFilename', '{config.exe_name or "app"}.exe'),
        StringStruct('ProductName', '{config.exe_name or "Python Application"}'),
        StringStruct('ProductVersion', '{config.version}')
      ])
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)"""
            
            fd, path = tempfile.mkstemp(suffix='.txt', prefix='version_')
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(version_content)
            return path
            
        except Exception as e:
            self.logger.error(f"Failed to create version file: {str(e)}")
            return None
    
    def _build_pyinstaller_command(self, config: BuildConfig, version_file: Optional[str]) -> List[str]:
        """Build PyInstaller command"""
        cmd = [
            sys.executable, "-m", "PyInstaller",
            config.script_path,
            "--noconfirm",
            "--clean",
            "--distpath", config.output_dir,
            "--workpath", "./build"
        ]
        
        if config.exe_name:
            cmd.extend(["--name", config.exe_name])
        
        if config.one_file:
            cmd.append("--onefile")
        
        if config.windowed:
            cmd.append("--windowed")
        
        if config.icon_path and Path(config.icon_path).exists():
            cmd.extend(["--icon", config.icon_path])
        
        if version_file:
            cmd.extend(["--version-file", version_file])
        
        for imp in config.hidden_imports:
            cmd.extend(["--hidden-import", imp])
        
        for exc in config.exclude_modules:
            cmd.extend(["--exclude-module", exc])
        
        for source, target in config.data_paths:
            if Path(source).exists():
                if Path(source).is_file():
                    cmd.extend(["--add-data", f"{source};{target}"])
                else:
                    cmd.extend(["--add-data", f"{source};{target}"])
        
        if config.use_upx:
            upx_path = shutil.which("upx")
            if upx_path:
                cmd.append("--upx-dir")
                cmd.append(str(Path(upx_path).parent))
        
        return cmd
    
    def _build_nuitka_command(self, config: BuildConfig) -> List[str]:
        """Build Nuitka command"""
        cmd = [
            sys.executable, "-m", "nuitka",
            config.script_path,
            "--output-dir=" + config.output_dir,
        ]
        
        if config.one_file:
            cmd.append("--onefile")
        
        if config.windowed:
            cmd.append("--windows-disable-console")
        
        if config.exe_name:
            cmd.append(f"--output-filename={config.exe_name}.exe")
        
        if config.icon_path and Path(config.icon_path).exists():
            cmd.append(f"--windows-icon-from-ico={config.icon_path}")
        
        for imp in config.hidden_imports:
            cmd.append(f"--include-module={imp}")
        
        for source, target in config.data_paths:
            if Path(source).exists():
                cmd.append(f"--include-data-files={source}={target}")
        
        return cmd
    
    def _execute_build_command(self, cmd: List[str], progress_callback: Optional[Callable[[str], Any]] = None) -> bool:
        """Execute build command with progress tracking"""
        try:
            self.logger.info("Starting build process...")
            self.logger.info(f"Command: {' '.join(cmd[:3])} ...")  # Log first few parts only
            
            self.current_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            if self.current_process.stdout is None:
                self.logger.error("Build process did not provide stdout")
                return False

            while True:
                if self.cancel_event.is_set():
                    self.current_process.terminate()
                    self.logger.info("Build cancelled by user")
                    return False
                
                line = self.current_process.stdout.readline()
                if not line:
                    break
                
                line = line.strip()
                if line:
                    self.logger.info(line)
                    if progress_callback:
                        progress_callback(line)
            
            self.current_process.wait()
            
            if self.current_process.returncode == 0:
                self.logger.info("Build completed successfully")
                return True
            else:
                self.logger.error(f"Build failed with exit code: {self.current_process.returncode}")
                return False
                
        except Exception as e:
            self.logger.error(f"Build execution failed: {str(e)}")
            return False
        finally:
            self.current_process = None

class NSISInstaller:
    """Advanced NSIS installer creation with signing support"""
    
    def __init__(self):
        self.logger = RotatingLogger()
        self.nsis_exe = NSIS_DIR / "nsis-3.09" / "makensis.exe"
    
    def ensure_nsis(self, progress_callback: Optional[Callable[[str], Any]] = None) -> bool:
        """Ensure NSIS is available, download if needed"""
        if self.nsis_exe.exists():
            self.logger.info("NSIS already available")
            return True
        
        self.logger.info("NSIS not found, downloading...")
        if progress_callback:
            progress_callback("Downloading NSIS...")
        
        zip_path = CACHE_DIR / "nsis.zip"
        
        # Download with verification
        if not ChecksumValidator.download_with_verification(
            NSIS_URL, zip_path, NSIS_CHECKSUM, NSIS_MIRRORS, progress_callback
        ):
            self.logger.error("Failed to download NSIS")
            return False
        
        try:
            if progress_callback:
                progress_callback("Extracting NSIS...")
            
            with zipfile.ZipFile(zip_path) as zf:
                zf.extractall(NSIS_DIR)
            
            if self.nsis_exe.exists():
                self.logger.info("NSIS setup completed successfully")
                zip_path.unlink()  # Cleanup
                return True
            else:
                self.logger.error("NSIS executable not found after extraction")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to extract NSIS: {str(e)}")
            return False
    
    def build_installer(self, installer_config: Optional[InstallerConfig] = None, build_config: Optional[BuildConfig] = None,
                       signing_config: Optional[SigningConfig] = None, progress_callback: Optional[Callable[[str], Any]] = None, **kwargs) -> bool:

        try:
            # Backwards compatibility: callers may pass exe_path and config kwargs
            if 'exe_path' in kwargs and 'config' in kwargs and installer_config is None and build_config is None:
                exe_path = Path(kwargs.get('exe_path')) # type: ignore
                installer_cfg = kwargs.get('config')
                # Create a minimal BuildConfig from exe_path
                build_cfg = BuildConfig(
                    script_path=str(exe_path),
                    exe_name=exe_path.stem,
                    output_dir=str(exe_path.parent)
                )
                installer_config = installer_cfg
                build_config = build_cfg

            if installer_config is None or build_config is None:
                self.logger.error("Installer or build configuration missing")
                return False
            if not self.ensure_nsis(progress_callback):
                return False
            
            # Validate build output exists
            if not self._validate_build_output(build_config):
                return False
            
            # Generate installer script
            script_content = self._generate_nsi_script(installer_config, build_config)
            
            # Write script to temporary file
            script_path = Path(tempfile.gettempdir()) / f"installer_{int(time.time())}.nsi"
            try:
                script_path.write_text(script_content, encoding='utf-8')
                
                # Build installer
                success = self._execute_nsis_build(script_path, progress_callback)
                
                if success:
                    installer_path = self._get_installer_path(installer_config)
                    
                    # Sign installer if configured
                    if signing_config and signing_config.cert_path:
                        success = self._sign_installer(installer_path, signing_config, progress_callback)
                
                return success
                
            finally:
                # Cleanup script file
                if script_path.exists():
                    script_path.unlink()
                    
        except Exception as e:
            self.logger.error(f"Installer build failed: {str(e)}")
            return False
    
    def _validate_build_output(self, build_config: BuildConfig) -> bool:
        """Validate that build output exists"""
        output_path = safe_path(getattr(build_config, 'output_dir', None)) / f"{build_config.exe_name}.exe"
        if not output_path.exists():
            self.logger.error(f"Build output not found: {output_path}")
            return False
        return True
    
    def _generate_nsi_script(self, installer_config: InstallerConfig, build_config: BuildConfig) -> str:
        """Generate NSIS script content"""
        exe_name = f"{build_config.exe_name}.exe"
        install_dir = installer_config.install_dir or f"$PROGRAMFILES\\{installer_config.app_name}"
        
        out_file_path = str(safe_path(getattr(installer_config, 'output_dir', None)) / f"{installer_config.app_name}_setup.exe")
        script = [
            '!include "MUI2.nsh"',
            f'Name "{installer_config.app_name}"',
            f'OutFile "{out_file_path}"',
            f'InstallDir "{install_dir}"',
            'RequestExecutionLevel ' + ('user' if installer_config.per_user else 'admin'),
            'Unicode True',
            'SetCompressor /SOLID lzma',
            '',
            '!define MUI_ABORTWARNING',
            '!insertmacro MUI_PAGE_WELCOME',
        ]
        
        if installer_config.eula_file:
            script.append(f'!insertmacro MUI_PAGE_LICENSE "{installer_config.eula_file}"')
        
        script.extend([
            '!insertmacro MUI_PAGE_DIRECTORY',
            '!insertmacro MUI_PAGE_INSTFILES',
            '!insertmacro MUI_PAGE_FINISH',
            '!insertmacro MUI_LANGUAGE "English"',
            '',
            'Section "Main" SEC01',
            '  SetOutPath "$INSTDIR"',
            f'  File "{str(safe_path(getattr(build_config, "output_dir", None)) / exe_name)}"',
        ])
        
        if installer_config.desktop_shortcut:
            script.append(f'  CreateShortCut "$DESKTOP\\{installer_config.app_name}.lnk" "$INSTDIR\\{exe_name}"')
        
        if installer_config.start_menu:
            script.append(f'  CreateDirectory "$SMPROGRAMS\\{installer_config.app_name}"')
            script.append(f'  CreateShortCut "$SMPROGRAMS\\{installer_config.app_name}\\{installer_config.app_name}.lnk" "$INSTDIR\\{exe_name}"')
        
        script.extend([
            'SectionEnd',
            '',
            'Section "Uninstall"',
            f'  Delete "$INSTDIR\\{exe_name}"',
            '  RMDir "$INSTDIR"',
            f'  Delete "$DESKTOP\\{installer_config.app_name}.lnk"',
            f'  Delete "$SMPROGRAMS\\{installer_config.app_name}\\{installer_config.app_name}.lnk"',
            f'  RMDir "$SMPROGRAMS\\{installer_config.app_name}"',
            'SectionEnd'
        ])
        
        return '\n'.join(script)
    
    def _execute_nsis_build(self, script_path: Path, progress_callback: Optional[Callable[[str], Any]] = None) -> bool:
        """Execute NSIS build command"""
        cmd = [str(self.nsis_exe), str(script_path)]
        
        if progress_callback:
            progress_callback("Compiling installer...")
        
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, universal_newlines=True
        )

        if process.stdout is None:
            self.logger.error("NSIS process did not provide stdout")
            return False

        for line in iter(process.stdout.readline, ''):
            self.logger.info(line.strip())
            if progress_callback:
                progress_callback(line.strip())
        
        return_code = process.wait()
        return return_code == 0
    
    def _get_installer_path(self, installer_config: InstallerConfig) -> str:
        """Get the path to the generated installer"""
        out_dir = safe_path(getattr(installer_config, 'output_dir', None))
        return str(out_dir / f"{installer_config.app_name}_setup.exe")
    
    def _sign_installer(self, installer_path: str, signing_config: Optional[SigningConfig], progress_callback: Optional[Callable[[str], Any]] = None) -> bool:
        if not signing_config:
            self.logger.warning("No signing configuration provided; skipping signing")
            return False
        """Sign the installer using signtool"""
        if progress_callback:
            progress_callback("Signing installer...")
        
        cmd = [
            "signtool.exe",  # Assume in PATH
            "sign",
            "/f", signing_config.cert_path,
            "/p", signing_config.cert_password,
            "/tr", signing_config.timestamp_server,
            "/td", "sha256",
            "/fd", "sha256",
            installer_path
        ]
        
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            self.logger.info(f"Installer signed: {installer_path}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Signing failed: {e.stderr}")
            return False
        except FileNotFoundError:
            self.logger.error("signtool.exe not found in PATH")
            return False

class ProjectTemplates:
    """Project templates for common application types"""
    
    @staticmethod
    def get_templates() -> Dict[str, Dict[str, Any]]:
        """Get available project templates"""
        return {
            "CLI Application": {
                "project": {
                    "name": "My CLI App",
                    "version": "1.0.0",
                    "author": "Your Name",
                    "description": "A command-line application",
                    "license": "MIT"
                },
                "build": {
                    "script_path": "",
                    "exe_name": "my_cli_app",
                    "output_dir": "./dist",
                    "one_file": True,
                    "windowed": False,
                    "clean_build": True,
                    "backend": "pyinstaller",
                    "hidden_imports": ["click", "argparse"]
                },
                "advanced": {
                    "optimization_level": 1,
                    "debug_mode": False,
                    "console_mode": True
                }
            },
            "GUI Application": {
                "project": {
                    "name": "My GUI App",
                    "version": "1.0.0",
                    "author": "Your Name",
                    "description": "A graphical user interface application",
                    "license": "MIT"
                },
                "build": {
                    "script_path": "",
                    "exe_name": "my_gui_app",
                    "output_dir": "./dist",
                    "one_file": True,
                    "windowed": True,
                    "clean_build": True,
                    "backend": "pyinstaller",
                    "icon_path": "",
                    "hidden_imports": ["tkinter", "customtkinter", "PIL"]
                },
                "advanced": {
                    "optimization_level": 1,
                    "debug_mode": False,
                    "console_mode": False
                }
            },
            "Web Service": {
                "project": {
                    "name": "My Web Service",
                    "version": "1.0.0",
                    "author": "Your Name",
                    "description": "A web service application",
                    "license": "MIT"
                },
                "build": {
                    "script_path": "",
                    "exe_name": "my_web_service",
                    "output_dir": "./dist",
                    "one_file": False,
                    "windowed": False,
                    "clean_build": True,
                    "backend": "pyinstaller",
                    "hidden_imports": ["flask", "werkzeug", "jinja2", "click"]
                },
                "advanced": {
                    "optimization_level": 2,
                    "debug_mode": False,
                    "console_mode": True
                }
            },
            "Data Science": {
                "project": {
                    "name": "My Data Science App",
                    "version": "1.0.0",
                    "author": "Your Name",
                    "description": "A data science application",
                    "license": "MIT"
                },
                "build": {
                    "script_path": "",
                    "exe_name": "my_data_app",
                    "output_dir": "./dist",
                    "one_file": False,
                    "windowed": False,
                    "clean_build": True,
                    "backend": "pyinstaller",
                    "hidden_imports": ["numpy", "pandas", "matplotlib", "scipy", "sklearn"]
                },
                "advanced": {
                    "optimization_level": 2,
                    "debug_mode": False,
                    "console_mode": True
                }
            },
            "Game": {
                "project": {
                    "name": "My Game",
                    "version": "1.0.0",
                    "author": "Your Name",
                    "description": "A game application",
                    "license": "MIT"
                },
                "build": {
                    "script_path": "",
                    "exe_name": "my_game",
                    "output_dir": "./dist",
                    "one_file": True,
                    "windowed": True,
                    "clean_build": True,
                    "backend": "pyinstaller",
                    "hidden_imports": ["pygame", "numpy"],
                    "data_paths": []
                },
                "advanced": {
                    "optimization_level": 1,
                    "debug_mode": False,
                    "console_mode": False
                }
            },
            "Desktop App (PyQt)": {
                "project": {
                    "name": "My Desktop App",
                    "version": "1.0.0",
                    "author": "Your Name",
                    "description": "A PyQt desktop application",
                    "license": "MIT"
                },
                "build": {
                    "script_path": "",
                    "exe_name": "my_desktop_app",
                    "output_dir": "./dist",
                    "one_file": True,
                    "windowed": True,
                    "clean_build": True,
                    "backend": "pyinstaller",
                    "hidden_imports": ["PyQt5", "PyQt5.QtCore", "PyQt5.QtGui", "PyQt5.QtWidgets"]
                },
                "advanced": {
                    "optimization_level": 1,
                    "debug_mode": False,
                    "console_mode": False
                }
            }
        }
    
    @staticmethod
    def create_from_template(template_name: str, custom_values: Optional[Dict[str, Any]] = None) -> ProjectConfig:
        """Create a project configuration from a template"""
        templates = ProjectTemplates.get_templates()
        if template_name not in templates:
            raise ValueError(f"Template '{template_name}' not found")
        
        template = templates[template_name]
        if custom_values:
            template = ProjectTemplates._merge_values(template, custom_values)
        
        # Convert to ProjectConfig
        config = ProjectConfig()
        config.project = ProjectInfo(**template["project"])
        config.build_profiles["default"] = BuildConfig(**template["build"])
        config.advanced = AdvancedConfig(**template["advanced"])
        
        return config
    
    @staticmethod
    def _merge_values(base: Dict[str, Any], custom: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively merge custom values into base template"""
        result = base.copy()
        for key, value in custom.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = ProjectTemplates._merge_values(result[key], value)
            else:
                result[key] = value
        return result

class ProjectManager:
    """Manages project configuration save/load"""
    
    def __init__(self):
        self.logger = RotatingLogger()
    
    def save_config(self, config: ProjectConfig, file_path: str) -> bool:
        """Save project configuration to JSON file"""
        try:
            # Convert dataclasses to dict
            config_dict = {
                'version': '2.0',
                'metadata': {
                    'created': datetime.now().isoformat(),
                    'py2win_version': APP_VERSION,
                    **config.metadata
                },
                'build': asdict(config.build),
                'installer': asdict(config.installer),
                'signing': ({**asdict(config.signing), 'cert_password': ''} if config.signing else {}),
            }
            
            # Create backup if file exists
            file_path_obj = Path(file_path)
            if file_path_obj.exists():
                backup_path = file_path_obj.with_suffix(f'.bak.{int(time.time())}')
                shutil.copy2(file_path_obj, backup_path)
                self.logger.info(f"Created backup: {backup_path}")
            
            # Write atomically
            temp_path = file_path_obj.with_suffix('.tmp')
            with open(temp_path, 'w', encoding='utf-8') as f:
                json.dump(config_dict, f, indent=2, ensure_ascii=False)
            
            temp_path.replace(file_path_obj)
            self.logger.info(f"Configuration saved: {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {str(e)}")
            return False
    
    def load_config(self, file_path: 'str | Path') -> Optional[ProjectConfig]:
        """Load project configuration from JSON file"""
        try:
            fp = str(file_path)
            with open(fp, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Validate schema version
            version = data.get('version', '1.0')
            if version not in ['1.0', '2.0']:
                self.logger.warning(f"Unsupported config version: {version}")
            
            # Create config objects
            build_config = BuildConfig(**data.get('build', {}))
            installer_config = InstallerConfig(**data.get('installer', {}))
            signing_config = SigningConfig(**data.get('signing')) if data.get('signing') else None

            config = ProjectConfig()
            config.build = build_config
            config.installer = installer_config
            config.signing = signing_config
            config.metadata = data.get('metadata', {})
            
            self.logger.info(f"Configuration loaded: {file_path}")
            return config
            
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {str(e)}")
            return None
    
    def get_recent_configs(self, max_count: int = 5) -> List[Path]:
        """Get list of recently used configuration files as Path objects"""
        recent_file = CONFIG_DIR / "recent_configs.json"
        try:
            if recent_file.exists():
                with open(recent_file, 'r') as f:
                    recent = json.load(f)
                    # Convert to Path and filter existing files
                    paths = [Path(p) for p in recent[:max_count]]
                    return [p for p in paths if p.exists()]
        except Exception:
            pass
        return []
    
    def add_recent_config(self, file_path: str):
        """Add configuration file to recent list"""
        recent_file = CONFIG_DIR / "recent_configs.json"
        try:
            recent = []
            if recent_file.exists():
                with open(recent_file, 'r') as f:
                    recent = json.load(f)
            
            # Remove if already exists
            if file_path in recent:
                recent.remove(file_path)
            
            # Add to front
            recent.insert(0, file_path)
            
            # Keep only latest 10
            recent = recent[:10]
            
            with open(recent_file, 'w') as f:
                json.dump(recent, f, indent=2)
                
        except Exception:
            pass  # Don't fail on recent files issues
    def save_template(self, template_name: str, config: ProjectConfig) -> bool:
        """Save a project configuration as a reusable template"""
        try:
            templates_dir = CONFIG_DIR / "templates"
            templates_dir.mkdir(parents=True, exist_ok=True)
            tpl_path = templates_dir / f"{template_name}.json"
            tpl = {
                'project': asdict(config.project),
                'build': asdict(config.build),
                'advanced': asdict(config.advanced)
            }
            with open(tpl_path, 'w', encoding='utf-8') as f:
                json.dump(tpl, f, indent=2, ensure_ascii=False)
            self.logger.info(f"Saved template: {tpl_path}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to save template: {e}")
            return False
class InputValidator:
    """Input validation and sanitization for security"""
    
    @staticmethod
    def validate_file_path(path: str) -> bool:
        """Validate file path for security"""
        if not path or not isinstance(path, str):
            return False
        
        # Check for directory traversal attempts
        if ".." in path or path.startswith("/") or ":" in path:
            return False
        
        # Check for valid file extension
        if not path.endswith(('.py', '.pyw')):
            return False
        
        return True
    
    @staticmethod
    def validate_executable_name(name: str) -> bool:
        """Validate executable name for security"""
        if not name or not isinstance(name, str):
            return False
        
        # Check for invalid characters
        invalid_chars = '<>:"/\\|?*'
        if any(char in name for char in invalid_chars):
            return False
        
        # Check length
        if len(name) > 50:
            return False
        
        return True
    
    @staticmethod
    def sanitize_input(text: str) -> str:
        """Sanitize user input"""
        if not text:
            return ""
        
        # Remove potentially dangerous characters
        dangerous_chars = ['<', '>', '"', "'", '&', ';', '|', '`', '$']
        for char in dangerous_chars:
            text = text.replace(char, '')
        
        return text.strip()
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL for security"""
        if not url or not isinstance(url, str):
            return False
        
        # Basic URL validation
        if not url.startswith(('http://', 'https://')):
            return False
        
        # Check for suspicious patterns
        suspicious = ['javascript:', 'data:', 'file:', 'ftp:']
        if any(pattern in url.lower() for pattern in suspicious):
            return False
        
        return True


def safe_path(p: Optional[str], default: Optional[Path] = None) -> Path:
    """Convert optional path-like strings to Path, providing a safe default.

    Treat empty strings or None as default (if provided) or the current directory.
    Returns a Path object.
    """
    if not p:
        return default or Path('.')
    try:
        return Path(p)
    except Exception:
        return default or Path('.')

class Py2WinMainApp(ctk.CTk):
    """Main Py2Win Premium application with modern UI and enterprise features"""
    
    def __init__(self):
        super().__init__()
        
        # Configure window
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("1600x1000")
        self.minsize(1200, 800)
        
        # Set theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Initialize components
        self.logger = RotatingLogger()
        self.dependency_analyzer = DependencyAnalyzer(sys.executable)
        self.import_detector = HiddenImportDetector()
        self.build_orchestrator = BuildOrchestrator()
        self.nsis_installer = NSISInstaller()
        self.project_manager = ProjectManager()
        self.secure_storage = SecureStorage()
        self.validator = InputValidator()
        
        # Application state
        self.current_config = ProjectConfig()
        self.wizard_mode = True
        self.current_build_future = None
        self.log_messages = []  # Store all log messages for filtering
        self.current_filter = "ALL"
        self.recent_projects = []  # Store recent projects
        
        # UI Setup
        self.setup_ui()
        
        # Start background tasks
        self.after(100, self.start_log_polling)
        self.after(1000, self.check_initial_setup)
    
    def setup_ui(self):
        """Setup the complete user interface"""
        # Configure main grid
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Create main components
        self.create_sidebar()
        self.create_header()
        self.create_main_content()
        self.create_console()
        self.create_status_bar()
        
        # Setup key bindings
        self.bind_all("<Control-s>", lambda _: self.save_project())
        self.bind_all("<Control-o>", lambda _: self.load_project())
        self.bind_all("<F5>", lambda _: self.start_build())
    
    def create_sidebar(self):
        """Create navigation sidebar"""
        self.sidebar = ModernFrame(self, width=280)
        self.sidebar.grid(row=0, column=0, rowspan=3, sticky="nsew", padx=(10, 5), pady=10)
        self.sidebar.grid_propagate(False)
        
        # Logo/Title
        title_frame = ModernFrame(self.sidebar)
        title_frame.pack(fill="x", padx=20, pady=(20, 10))
        
        app_title = ctk.CTkLabel(
            title_frame,
            text=APP_NAME,
            font=ctk.CTkFont(size=22, weight="bold")
        )
        app_title.pack()
        
        version_label = ctk.CTkLabel(
            title_frame,
            text=f"v{APP_VERSION}",
            font=ctk.CTkFont(size=12),
            text_color=COLORS['text_secondary']
        )
        version_label.pack()
        
        # Recent Projects Section
        recent_frame = ModernFrame(self.sidebar)
        recent_frame.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkLabel(recent_frame, text="Recent Projects", font=ctk.CTkFont(size=12, weight="bold")).pack(pady=5)
        
        self.recent_var = ctk.StringVar(value="No recent projects")
        self.recent_menu = ctk.CTkOptionMenu(
            recent_frame,
            variable=self.recent_var,
            values=["No recent projects"],
            command=self.load_recent_project,
            width=200
        )
        self.recent_menu.pack(pady=5)
        
        # Load recent projects
        self.load_recent_projects()
        
        # Mode toggle
        mode_frame = ModernFrame(self.sidebar)
        mode_frame.pack(fill="x", padx=20, pady=10)
        
        self.mode_var = ctk.StringVar(value="Wizard" if self.wizard_mode else "Advanced")
        mode_toggle = ctk.CTkSegmentedButton(
            mode_frame,
            values=["Wizard", "Advanced"],
            variable=self.mode_var,
            command=self.toggle_mode
        )
        mode_toggle.pack(fill="x")
        
        # Navigation
        nav_frame = ModernFrame(self.sidebar)
        nav_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        self.nav_buttons = {}
        nav_items = [
            ("🏠", "Build", self.show_build_tab),
            ("📦", "Dependencies", self.show_dependencies_tab),
            ("🔍", "Imports", self.show_imports_tab),
            ("📁", "Assets", self.show_assets_tab),
            ("💿", "Installer", self.show_installer_tab),
            ("🔧", "Settings", self.show_settings_tab),
            ("⚡", "JSON Tools", self.show_json_tab)
        ]
        
        for icon, text, command in nav_items:
            btn = ModernButton(
                nav_frame,
                text=f"{icon} {text}",
                command=command,
                width=220,
                height=45,
                anchor="w",
                font=ctk.CTkFont(size=13)
            )
            btn.pack(pady=3, fill="x")
            self.nav_buttons[text] = btn
        
        # Quick actions
        actions_frame = ModernFrame(self.sidebar)
        actions_frame.pack(side="bottom", fill="x", padx=20, pady=20)
        
        quick_build_btn = ModernButton(
            actions_frame,
            text="🚀 Quick Build",
            command=self.quick_build,
            height=40,
            fg_color=COLORS['success'],
            font=ctk.CTkFont(size=12, weight="bold")
        )
        quick_build_btn.pack(fill="x", pady=5)
        
        # Project management
        project_frame = ctk.CTkFrame(actions_frame, height=80)
        project_frame.pack(fill="x", pady=5)
        project_frame.pack_propagate(False)
        
        save_btn = ModernButton(project_frame, text="💾", command=self.save_project, width=35, height=35)
        save_btn.pack(side="left", padx=2, pady=5)
        
        load_btn = ModernButton(project_frame, text="📂", command=self.load_project, width=35, height=35)
        load_btn.pack(side="left", padx=2, pady=5)
        
        new_btn = ModernButton(project_frame, text="📄", command=self.new_project, width=35, height=35)
        new_btn.pack(side="left", padx=2, pady=5)
    
    def create_header(self):
        """Create header with breadcrumbs and actions"""
        self.header = ModernFrame(self, height=60)
        self.header.grid(row=0, column=1, sticky="ew", padx=(5, 10), pady=(10, 5))
        self.header.grid_propagate(False)
        self.header.grid_columnconfigure(1, weight=1)
        
        # Current tab indicator
        self.breadcrumb_label = ctk.CTkLabel(
            self.header,
            text="Build Configuration",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        self.breadcrumb_label.grid(row=0, column=0, sticky="w", padx=20, pady=15)
        
        # Action buttons
        action_frame = ctk.CTkFrame(self.header)
        action_frame.grid(row=0, column=2, sticky="e", padx=20, pady=10)
        
        self.cancel_btn = ModernButton(
            action_frame,
            text="❌ Cancel Build",
            command=self.cancel_build,
            fg_color=COLORS['error'],
            state="disabled"
        )
        self.cancel_btn.pack(side="right", padx=5)
    
    def create_main_content(self):
        """Create main content area with tabs"""
        self.main_frame = ModernFrame(self)
        self.main_frame.grid(row=1, column=1, sticky="nsew", padx=(5, 10), pady=5)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=1)
        
        # Tab content frames
        self.tab_frames = {}
        self.current_tab = "Build"
        
        # Create all tabs
        self.create_build_tab()
        self.create_dependencies_tab()
        self.create_imports_tab()
        self.create_assets_tab()
        self.create_installer_tab()
        self.create_settings_tab()
        self.create_json_tab()
        
        # Show initial tab
        self.show_build_tab()
    
    def create_console(self):
        """Create console output area"""
        console_frame = ModernFrame(self, height=220)
        console_frame.grid(row=2, column=1, sticky="ew", padx=(5, 10), pady=5)
        console_frame.grid_propagate(False)
        console_frame.grid_columnconfigure(0, weight=1)
        console_frame.grid_rowconfigure(1, weight=1)
        
        # Console header
        console_header = ctk.CTkFrame(console_frame)
        console_header.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 0))
        console_header.grid_columnconfigure(1, weight=1)
        
        console_title = ctk.CTkLabel(
            console_header,
            text="📋 Console Output",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        console_title.grid(row=0, column=0, sticky="w", padx=10, pady=8)
        
        # Console controls
        console_controls = ctk.CTkFrame(console_header)
        console_controls.grid(row=0, column=2, sticky="e", padx=10, pady=5)
        
        clear_btn = ModernButton(console_controls, text="🗑️", command=self.clear_console, width=30, height=30)
        clear_btn.pack(side="right", padx=2)
        
        copy_btn = ModernButton(console_controls, text="📋", command=self.copy_console, width=30, height=30)
        copy_btn.pack(side="right", padx=2)
        
        # Filter buttons
        filter_frame = ctk.CTkFrame(console_header)
        filter_frame.grid(row=0, column=1, sticky="", padx=20)
        
        self.log_filter = ctk.StringVar(value="ALL")
        filter_menu = ctk.CTkSegmentedButton(
            filter_frame,
            values=["ALL", "INFO", "WARNING", "ERROR"],
            variable=self.log_filter,
            command=self.filter_logs
        )
        filter_menu.pack()
        
        # Console text area
        self.console_text = ctk.CTkTextbox(
            console_frame,
            font=ctk.CTkFont(family="Consolas", size=11),
            height=150
        )
        self.console_text.grid(row=1, column=0, sticky="nsew", padx=10, pady=(5, 10))
    
    def create_status_bar(self):
        """Create bottom status bar"""
        self.status_bar = ctk.CTkFrame(self, height=40)
        self.status_bar.grid(row=3, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 10))
        self.status_bar.grid_propagate(False)
        self.status_bar.grid_columnconfigure(1, weight=1)
        
        # Status text
        self.status_label = ctk.CTkLabel(
            self.status_bar,
            text="Ready",
            font=ctk.CTkFont(size=12)
        )
        self.status_label.grid(row=0, column=0, sticky="w", padx=15, pady=10)
        
        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(self.status_bar, height=15)
        self.progress_bar.grid(row=0, column=1, sticky="ew", padx=20, pady=10)
        self.progress_bar.set(0)
        
        # Status indicators
        indicators_frame = ctk.CTkFrame(self.status_bar)
        indicators_frame.grid(row=0, column=2, sticky="e", padx=15, pady=5)
        
        self.python_status = ctk.CTkLabel(indicators_frame, text="🐍 Python OK", font=ctk.CTkFont(size=11))
        self.python_status.pack(side="left", padx=5)
        
        self.deps_status = ctk.CTkLabel(indicators_frame, text="📦 Checking...", font=ctk.CTkFont(size=11))
        self.deps_status.pack(side="left", padx=5)
    
    def create_build_tab(self):
        """Create build configuration tab"""
        frame = ModernFrame(self.main_frame)
        self.tab_frames["Build"] = frame
        
        # Use notebook for wizard/advanced modes
        self.build_notebook = ctk.CTkTabview(frame)
        self.build_notebook.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Wizard mode tab
        wizard_tab = self.build_notebook.add("🧙 Wizard Mode")
        self.create_wizard_build_ui(wizard_tab)
        
        # Advanced mode tab  
        advanced_tab = self.build_notebook.add("⚙️ Advanced Mode")
        self.create_advanced_build_ui(advanced_tab)
    
    def create_wizard_build_ui(self, parent):
        """Create simplified wizard mode UI"""
        scroll_frame = ctk.CTkScrollableFrame(parent)
        scroll_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Build Profile Selection
        profile_frame = ctk.CTkFrame(scroll_frame)
        profile_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(profile_frame, text="Build Profile:", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=5)
        
        profile_controls = ctk.CTkFrame(profile_frame, fg_color="transparent")
        profile_controls.pack(fill="x", padx=10, pady=5)
        
        self.profile_var = ctk.StringVar(value="default")
        self.profile_menu = ctk.CTkOptionMenu(
            profile_controls,
            values=["default"],
            variable=self.profile_var,
            command=self.switch_build_profile,
            width=200
        )
        self.profile_menu.pack(side="left", padx=5)
        
        self.add_profile_btn = ModernButton(
            profile_controls,
            text="+ Add Profile",
            command=self.add_build_profile,
            width=100
        )
        self.add_profile_btn.pack(side="left", padx=5)
        
        self.remove_profile_btn = ModernButton(
            profile_controls,
            text="- Remove",
            command=self.remove_build_profile,
            width=100,
            fg_color=COLORS['error']
        )
        self.remove_profile_btn.pack(side="left", padx=5)
        
        # Template Selection
        template_frame = ctk.CTkFrame(scroll_frame)
        template_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(template_frame, text="Project Template:", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=5)
        
        template_controls = ctk.CTkFrame(template_frame, fg_color="transparent")
        template_controls.pack(fill="x", padx=10, pady=5)
        
        self.template_var = ctk.StringVar(value="Select Template")
        self.template_menu = ctk.CTkOptionMenu(
            template_controls,
            values=["Select Template"] + list(ProjectTemplates.get_templates().keys()),
            variable=self.template_var,
            command=self.load_template,
            width=250
        )
        self.template_menu.pack(side="left", padx=5)
        
        self.save_template_btn = ModernButton(
            template_controls,
            text="Save as Template",
            command=self.save_as_template,
            width=120
        )
        self.save_template_btn.pack(side="left", padx=5)
        scroll_frame.grid_columnconfigure(1, weight=1)
        
        # Step 1: Select Python script
        step1_frame = ModernFrame(scroll_frame)
        step1_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=10)
        step1_frame.grid_columnconfigure(1, weight=1)
        
        step1_title = ctk.CTkLabel(step1_frame, text="📁 Step 1: Select Your Python Script", 
                                  font=ctk.CTkFont(size=16, weight="bold"))
        step1_title.grid(row=0, column=0, columnspan=3, sticky="w", padx=20, pady=15)
        
        self.wizard_script_entry = ctk.CTkEntry(step1_frame, placeholder_text="Choose your main Python file...")
        self.wizard_script_entry.grid(row=1, column=0, columnspan=2, sticky="ew", padx=20, pady=10)
        
        browse_script_btn = ModernButton(step1_frame, text="Browse", command=self.wizard_browse_script)
        browse_script_btn.grid(row=1, column=2, padx=(10, 20), pady=10)
        
        # Step 2: Basic options
        step2_frame = ModernFrame(scroll_frame)
        step2_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=10)
        
        step2_title = ctk.CTkLabel(step2_frame, text="⚙️ Step 2: Basic Options", 
                                  font=ctk.CTkFont(size=16, weight="bold"))
        step2_title.grid(row=0, column=0, columnspan=2, sticky="w", padx=20, pady=15)
        
        options_inner = ctk.CTkFrame(step2_frame)
        options_inner.grid(row=1, column=0, columnspan=2, sticky="ew", padx=20, pady=10)
        options_inner.grid_columnconfigure((0, 1), weight=1)
        
        self.wizard_windowed_var = ctk.BooleanVar(value=True)
        windowed_cb = ctk.CTkCheckBox(options_inner, text="Hide Console Window", variable=self.wizard_windowed_var)
        windowed_cb.grid(row=0, column=0, sticky="w", padx=20, pady=10)
        
        self.wizard_onefile_var = ctk.BooleanVar(value=True)
        onefile_cb = ctk.CTkCheckBox(options_inner, text="Single EXE File", variable=self.wizard_onefile_var)
        onefile_cb.grid(row=0, column=1, sticky="w", padx=20, pady=10)
        
        # Step 3: Build
        step3_frame = ModernFrame(scroll_frame)
        step3_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=10)
        
        step3_title = ctk.CTkLabel(step3_frame, text="🚀 Step 3: Build Your Application", 
                                  font=ctk.CTkFont(size=16, weight="bold"))
        step3_title.grid(row=0, column=0, sticky="w", padx=20, pady=15)
        
        wizard_build_btn = ModernButton(
            step3_frame,
            text="🚀 Build Application",
            command=self.wizard_build,
            height=60,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color=COLORS['primary']
        )
        wizard_build_btn.grid(row=1, column=0, sticky="ew", padx=20, pady=20)
    
    def create_advanced_build_ui(self, parent):
        """Create full advanced mode UI"""
        scroll_frame = ctk.CTkScrollableFrame(parent)
        scroll_frame.pack(fill="both", expand=True, padx=10, pady=10)
        scroll_frame.grid_columnconfigure(1, weight=1)
        
        row = 0
        
        # Script selection
        ctk.CTkLabel(scroll_frame, text="Python Script:", font=ctk.CTkFont(weight="bold")).grid(
            row=row, column=0, sticky="w", padx=10, pady=5)
        
        script_frame = ctk.CTkFrame(scroll_frame)
        script_frame.grid(row=row, column=1, sticky="ew", padx=10, pady=5)
        script_frame.grid_columnconfigure(0, weight=1)
        
        self.script_entry = ctk.CTkEntry(script_frame)
        self.script_entry.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        
        script_browse_btn = ModernButton(script_frame, text="Browse", command=self.browse_script)
        script_browse_btn.grid(row=0, column=1, padx=(0, 10), pady=10)
        
        row += 1
        
        # Executable name
        ctk.CTkLabel(scroll_frame, text="Executable Name:", font=ctk.CTkFont(weight="bold")).grid(
            row=row, column=0, sticky="w", padx=10, pady=5)
        self.exe_name_entry = ctk.CTkEntry(scroll_frame)
        self.exe_name_entry.grid(row=row, column=1, sticky="ew", padx=10, pady=5)
        
        row += 1
        
        # Output directory
        ctk.CTkLabel(scroll_frame, text="Output Directory:", font=ctk.CTkFont(weight="bold")).grid(
            row=row, column=0, sticky="w", padx=10, pady=5)
        
        output_frame = ctk.CTkFrame(scroll_frame)
        output_frame.grid(row=row, column=1, sticky="ew", padx=10, pady=5)
        output_frame.grid_columnconfigure(0, weight=1)
        
        self.output_dir_entry = ctk.CTkEntry(output_frame)
        self.output_dir_entry.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        self.output_dir_entry.insert(0, "./dist")
        
        output_browse_btn = ModernButton(output_frame, text="Browse", command=self.browse_output_dir)
        output_browse_btn.grid(row=0, column=1, padx=(0, 10), pady=10)
        
        row += 1
        
        # Icon file
        ctk.CTkLabel(scroll_frame, text="Icon File (Optional):", font=ctk.CTkFont(weight="bold")).grid(
            row=row, column=0, sticky="w", padx=10, pady=5)
        
        icon_frame = ctk.CTkFrame(scroll_frame)
        icon_frame.grid(row=row, column=1, sticky="ew", padx=10, pady=5)
        icon_frame.grid_columnconfigure(0, weight=1)
        
        self.icon_entry = ctk.CTkEntry(icon_frame)
        self.icon_entry.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        
        icon_browse_btn = ModernButton(icon_frame, text="Browse", command=self.browse_icon)
        icon_browse_btn.grid(row=0, column=1, padx=(0, 10), pady=10)
        
        row += 1
        
        # Version info
        version_frame = ModernFrame(scroll_frame)
        version_frame.grid(row=row, column=0, columnspan=2, sticky="ew", padx=10, pady=10)
        version_frame.grid_columnconfigure((1, 3), weight=1)
        
        version_title = ctk.CTkLabel(version_frame, text="Version Information", 
                                    font=ctk.CTkFont(size=14, weight="bold"))
        version_title.grid(row=0, column=0, columnspan=4, sticky="w", padx=15, pady=10)
        
        ctk.CTkLabel(version_frame, text="Version:").grid(row=1, column=0, sticky="w", padx=15, pady=5)
        self.version_entry = ctk.CTkEntry(version_frame)
        self.version_entry.grid(row=1, column=1, sticky="ew", padx=10, pady=5)
        self.version_entry.insert(0, "1.0.0")
        
        ctk.CTkLabel(version_frame, text="Company:").grid(row=1, column=2, sticky="w", padx=15, pady=5)
        self.company_entry = ctk.CTkEntry(version_frame)
        self.company_entry.grid(row=1, column=3, sticky="ew", padx=(10, 15), pady=5)
        
        ctk.CTkLabel(version_frame, text="Description:").grid(row=2, column=0, sticky="w", padx=15, pady=5)
        self.description_entry = ctk.CTkEntry(version_frame)
        self.description_entry.grid(row=2, column=1, columnspan=3, sticky="ew", padx=(10, 15), pady=5)
        
        row += 1
        
        # Build options
        options_frame = ModernFrame(scroll_frame)
        options_frame.grid(row=row, column=0, columnspan=2, sticky="ew", padx=10, pady=10)
        options_frame.grid_columnconfigure((0, 1, 2), weight=1)
        
        options_title = ctk.CTkLabel(options_frame, text="Build Options", 
                                    font=ctk.CTkFont(size=14, weight="bold"))
        options_title.grid(row=0, column=0, columnspan=3, sticky="w", padx=15, pady=10)
        
        self.onefile_var = ctk.BooleanVar(value=True)
        onefile_cb = ctk.CTkCheckBox(options_frame, text="Single File", variable=self.onefile_var)
        onefile_cb.grid(row=1, column=0, sticky="w", padx=15, pady=8)
        
        self.windowed_var = ctk.BooleanVar(value=True)
        windowed_cb = ctk.CTkCheckBox(options_frame, text="Windowed", variable=self.windowed_var)
        windowed_cb.grid(row=1, column=1, sticky="w", padx=15, pady=8)
        
        self.clean_var = ctk.BooleanVar(value=True)
        clean_cb = ctk.CTkCheckBox(options_frame, text="Clean Build", variable=self.clean_var)
        clean_cb.grid(row=1, column=2, sticky="w", padx=15, pady=8)
        
        self.upx_var = ctk.BooleanVar(value=False)
        upx_cb = ctk.CTkCheckBox(options_frame, text="UPX Compression", variable=self.upx_var)
        upx_cb.grid(row=2, column=0, sticky="w", padx=15, pady=8)
        
        # Backend selection
        ctk.CTkLabel(options_frame, text="Backend:").grid(row=2, column=1, sticky="w", padx=15, pady=8)
        self.backend_var = ctk.StringVar(value="pyinstaller")
        backend_menu = ctk.CTkOptionMenu(
            options_frame,
            values=["pyinstaller", "nuitka"],
            variable=self.backend_var
        )
        backend_menu.grid(row=2, column=2, sticky="ew", padx=15, pady=8)
        
        row += 1
        
        # Build button
        build_btn = ModernButton(
            scroll_frame,
            text="🚀 Build Executable",
            command=self.start_build,
            height=50,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color=COLORS['primary']
        )
        build_btn.grid(row=row, column=0, columnspan=2, sticky="ew", padx=10, pady=20)
    
    def create_dependencies_tab(self):
        """Create dependencies management tab"""
        frame = ModernFrame(self.main_frame)
        self.tab_frames["Dependencies"] = frame
        
        # Main content
        content = ctk.CTkScrollableFrame(frame)
        content.pack(fill="both", expand=True, padx=20, pady=20)
        content.grid_columnconfigure(0, weight=1)
        
        # Header
        header_frame = ModernFrame(content)
        header_frame.pack(fill="x", pady=(0, 20))
        header_frame.grid_columnconfigure(1, weight=1)
        
        title = ctk.CTkLabel(
            header_frame,
            text="📦 Dependency Management",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        title.grid(row=0, column=0, sticky="w", padx=20, pady=15)
        
        # Action buttons
        actions_frame = ctk.CTkFrame(header_frame)
        actions_frame.grid(row=0, column=2, sticky="e", padx=20, pady=10)
        
        diagnose_btn = ModernButton(
            actions_frame,
            text="🔍 Full Diagnosis",
            command=self.run_dependency_diagnosis
        )
        diagnose_btn.pack(side="left", padx=5)
        
        install_btn = ModernButton(
            actions_frame,
            text="📥 Install Missing",
            command=self.install_missing_dependencies,
            fg_color=COLORS['success']
        )
        install_btn.pack(side="left", padx=5)
        
        # Status cards
        self.deps_status_frame = ctk.CTkFrame(content)
        self.deps_status_frame.pack(fill="x", pady=10)
        
        # Results area
        results_label = ctk.CTkLabel(
            content,
            text="📋 Diagnosis Results",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        results_label.pack(anchor="w", pady=(20, 10))
        
        self.deps_results_text = ctk.CTkTextbox(content, height=400)
        self.deps_results_text.pack(fill="both", expand=True)
    
    # Event handlers and utility methods
    def toggle_mode(self, mode):
        """Toggle between wizard and advanced modes"""
        self.wizard_mode = (mode == "Wizard")
        if hasattr(self, 'build_notebook'):
            if self.wizard_mode:
                self.build_notebook.set("🧙 Wizard Mode")
            else:
                self.build_notebook.set("⚙️ Advanced Mode")
    
    def show_tab(self, tab_name):
        """Show specified tab and update UI"""
        # Hide current tab
        if hasattr(self, 'current_tab') and self.current_tab in self.tab_frames:
            self.tab_frames[self.current_tab].pack_forget()
        
        # Show new tab
        if tab_name in self.tab_frames:
            self.tab_frames[tab_name].pack(fill="both", expand=True)
            self.current_tab = tab_name
            
            # Update breadcrumb
            self.breadcrumb_label.configure(text=f"📍 {tab_name}")
            
            # Update navigation button styles
            for name, button in self.nav_buttons.items():
                if name == tab_name:
                    button.configure(fg_color=COLORS['primary'])
                else:
                    button.configure(fg_color=("gray75", "gray25"))
    
    # Navigation methods
    def show_build_tab(self): self.show_tab("Build")
    def show_dependencies_tab(self): self.show_tab("Dependencies") 
    def show_imports_tab(self): self.show_tab("Imports")
    def show_assets_tab(self): self.show_tab("Assets")
    def show_installer_tab(self): self.show_tab("Installer")
    def show_settings_tab(self): self.show_tab("Settings")
    def show_json_tab(self): self.show_tab("JSON Tools")
    
    # File browsing methods
    def browse_script(self):
        """Browse for Python script file"""
        filename = filedialog.askopenfilename(
            title="Select Python Script",
            filetypes=[("Python files", "*.py *.pyw"), ("All files", "*.*")]
        )
        if filename:
            self.script_entry.delete(0, tk.END)
            self.script_entry.insert(0, filename)
            
            # Auto-fill exe name if empty
            if not self.exe_name_entry.get():
                name = Path(filename).stem
                self.exe_name_entry.delete(0, tk.END)
                self.exe_name_entry.insert(0, name)
    
    def wizard_browse_script(self):
        """Browse script for wizard mode"""
        filename = filedialog.askopenfilename(
            title="Select Your Python Script",
            filetypes=[("Python files", "*.py *.pyw"), ("All files", "*.*")]
        )
        if filename:
            self.wizard_script_entry.delete(0, tk.END)
            self.wizard_script_entry.insert(0, filename)
    
    def browse_output_dir(self):
        """Browse for output directory"""
        dirname = filedialog.askdirectory(title="Select Output Directory")
        if dirname:
            self.output_dir_entry.delete(0, tk.END)
            self.output_dir_entry.insert(0, dirname)
    
    
    # Build and project management methods
    def quick_build(self):
        """Quick build using current wizard settings"""
        if not self.wizard_script_entry.get():
            messagebox.showerror("Error", "Please select a Python script first")
            return
        
        # Update config from wizard settings
        self.current_config.build.script_path = self.wizard_script_entry.get()
        self.current_config.build.exe_name = Path(self.wizard_script_entry.get()).stem
        self.current_config.build.windowed = self.wizard_windowed_var.get()
        self.current_config.build.one_file = self.wizard_onefile_var.get()
        
        self.start_build()
    
    def wizard_build(self):
        """Build from wizard mode"""
        self.quick_build()
    
    def start_build(self):
        """Start the build process"""
        if not self._validate_build_inputs():
            return
        
        self._update_config_from_ui()
        
        def build_worker():
            try:
                self.after(0, lambda: self.set_build_status(True))
                success = self.build_orchestrator.build(
                    self.current_config.build,
                    progress_callback=self.update_build_progress
                )
                self.after(0, lambda: self.on_build_complete(success))
            except Exception as e:
                self.logger.error(f"Build error: {str(e)}")
                self.after(0, lambda: self.on_build_complete(False))
        
        # Start build in background thread
        self.current_build_future = threading.Thread(target=build_worker, daemon=True)
        self.current_build_future.start()
    
    def cancel_build(self):
        """Cancel current build"""
        if self.current_build_future and self.current_build_future.is_alive():
            self.build_orchestrator.cancel_build()
            self.set_build_status(False)
            self.update_status("Build cancelled")
    
    def set_build_status(self, building: bool):
        """Update UI for build state"""
        self.cancel_btn.configure(state="normal" if building else "disabled")
        if building:
            self.progress_bar.configure(mode="indeterminate")
            self.progress_bar.start()
        else:
            self.progress_bar.stop()
            self.progress_bar.configure(mode="determinate")
            self.progress_bar.set(0)
    
    def update_build_progress(self, message: str):
        """Update build progress in UI thread"""
        self.after(0, lambda: self.update_status(message))
    
    def on_build_complete(self, success: bool):
        """Handle build completion"""
        self.set_build_status(False)
        if success:
            self.update_status("Build completed successfully!")
            messagebox.showinfo("Success", "Build completed successfully!")
        else:
            self.update_status("Build failed - check console for details")
            messagebox.showerror("Build Failed", "Build failed. Check the console output for details.")
    
    def _validate_build_inputs(self) -> bool:
        """Validate build inputs"""
        if self.wizard_mode:
            script_path = self.wizard_script_entry.get()
        else:
            script_path = self.script_entry.get()
        
        if not script_path:
            messagebox.showerror("Error", "Please select a Python script")
            return False
        
        if not Path(script_path).exists():
            messagebox.showerror("Error", "Selected Python script does not exist")
            return False
        
        return True
    
    # (Public wrapper `_update_config_from_ui` is defined later and delegates to the implementation)
    
    # Project management
    def save_project(self):
        """Save current project configuration"""
        filename = filedialog.asksaveasfilename(
            title="Save Project Configuration",
            defaultextension=".py2win.json",
            filetypes=[("Py2Win Project", "*.py2win.json"), ("JSON files", "*.json")]
        )
        if filename:
            self._update_config_from_ui()
            if self.project_manager.save_config(self.current_config, filename):
                self.project_manager.add_recent_config(filename)
                self.update_status(f"Project saved: {Path(filename).name}")
                messagebox.showinfo("Success", "Project configuration saved successfully!")
            else:
                messagebox.showerror("Error", "Failed to save project configuration")
    
    def load_project(self):
        """Load project configuration"""
        filename = filedialog.askopenfilename(
            title="Load Project Configuration",
            filetypes=[("Py2Win Project", "*.py2win.json"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            config = self.project_manager.load_config(filename)
            if config:
                self.current_config = config
                self._update_ui_from_config()
                self.project_manager.add_recent_config(filename)
                self.update_status(f"Project loaded: {Path(filename).name}")
                messagebox.showinfo("Success", "Project configuration loaded successfully!")
            else:
                messagebox.showerror("Error", "Failed to load project configuration")
    
    def new_project(self):
        """Create new project"""
        self.current_config = ProjectConfig()
        self._update_ui_from_config()
        self.update_status("New project created")
    
    def _update_ui_from_config(self):
        """Public wrapper: update UI from current configuration by delegating to implementation."""
        impl = getattr(self, '_update_ui_impl', None)
        if callable(impl):
            return impl()
        return None

    def _update_config_from_ui(self):
        """Public wrapper: update configuration from UI inputs by delegating to implementation."""
        impl = getattr(self, '_update_config_impl', None)
        if callable(impl):
            return impl()
        return None
    
    # Console management
    def start_log_polling(self):
        """Start polling for log messages"""
        # Implement robust log polling with error handling
        try:
            while True:
                try:
                    message = self.logger.log_queue.get_nowait()
                    if not isinstance(message, str):
                        continue
                    self.append_to_console(str(message).strip())
                except queue.Empty:
                    break
                except Exception as e:
                    print(f"Log polling error: {e}")
                    break
        except Exception:
            pass  # Silently handle outer exceptions to prevent UI freezes
        
        # Schedule next poll
        self.after(100, self.start_log_polling)
    
    def append_to_console(self, message: str, level: str = "INFO"):
        """Append message to console with proper filtering"""
        if not message.strip():
            return
        
        # Add timestamp if not present
        if not message.startswith('['):
            timestamp = datetime.now().strftime('%H:%M:%S')
            message = f"[{timestamp}] {message}"
        
        # Store message for filtering
        self.log_messages.append((level, message))
        
        # Limit stored messages
        if len(self.log_messages) > 1000:
            self.log_messages = self.log_messages[-500:]
        
        # Check if message should be displayed based on current filter
        should_display = False
        if self.current_filter == "ALL":
            should_display = True
        elif self.current_filter == "INFO" and level in ["INFO", "SUCCESS", "WARNING", "ERROR"]:
            should_display = True
        elif self.current_filter == "WARNING" and level in ["WARNING", "ERROR"]:
            should_display = True
        elif self.current_filter == "ERROR" and level == "ERROR":
            should_display = True
        
        if should_display:
            self.console_text.insert(tk.END, message + "\n")
            self.console_text.see(tk.END)
            
            # Limit console display size
            lines = self.console_text.get("1.0", tk.END).split('\n')
            if len(lines) > 1000:
                self.console_text.delete("1.0", f"{len(lines) - 500}.0")
    
    def clear_console(self):
        """Clear console output"""
        self.console_text.delete("1.0", tk.END)
        self.log_messages.clear()
    
    def log_message(self, message: str, level: str = "INFO"):
        """Log a message to the console with proper level"""
        # Map level names to colors for display
        level_prefixes = {
            "INFO": "[INFO]",
            "SUCCESS": "[✓]",
            "WARNING": "[⚠]",
            "ERROR": "[✗]",
            "DEBUG": "[DEBUG]"
        }
        
        prefix = level_prefixes.get(level, "[INFO]")
        formatted_message = f"{prefix} {message}"
        
        self.append_to_console(formatted_message, level)
    
    def copy_console(self):
        """Copy console content to clipboard"""
        content = self.console_text.get("1.0", tk.END)
        self.clipboard_clear()
        self.clipboard_append(content)
        self.update_status("Console content copied to clipboard")
    
    def filter_logs(self, level: str):
        """Filter console logs by level"""
        self.current_filter = level
        
        # Clear console
        self.console_text.delete("1.0", tk.END)
        
        # Re-display filtered messages
        for msg_level, msg_text in self.log_messages:
            if level == "ALL":
                self.console_text.insert(tk.END, msg_text + "\n")
            elif level == "INFO" and msg_level in ["INFO", "SUCCESS", "WARNING", "ERROR"]:
                self.console_text.insert(tk.END, msg_text + "\n")
            elif level == "WARNING" and msg_level in ["WARNING", "ERROR"]:
                self.console_text.insert(tk.END, msg_text + "\n")
            elif level == "ERROR" and msg_level == "ERROR":
                self.console_text.insert(tk.END, msg_text + "\n")
        
        self.console_text.see(tk.END)
        self.update_status(f"Log filter: {level}")
    
    # Dependency management
    def check_initial_setup(self):
        """Check initial setup on startup"""
        threading.Thread(target=self._check_setup_worker, daemon=True).start()
    
    def _check_setup_worker(self):
        """Background worker for setup checking"""
        # Check Python version
        version_info = self.dependency_analyzer._check_python_version()
        if version_info['supported']:
            self.after(0, lambda: self.python_status.configure(text="🐍 Python OK", text_color="green"))
        else:
            self.after(0, lambda: self.python_status.configure(text="🐍 Python Old", text_color="orange"))
        
        # Check dependencies
        missing = self.dependency_analyzer._check_missing_packages()
        if not missing:
            self.after(0, lambda: self.deps_status.configure(text="📦 Deps OK", text_color="green"))
        else:
            self.after(0, lambda: self.deps_status.configure(text=f"📦 Missing {len(missing)}", text_color="orange"))
    
    def run_dependency_diagnosis(self):
        """Run full dependency diagnosis"""
        def diagnosis_worker():
            try:
                self.after(0, lambda: self.update_status("Running dependency diagnosis..."))
                results = self.dependency_analyzer.full_diagnosis()
                self.after(0, lambda: self._show_diagnosis_results(results))
            except Exception as e:
                self.logger.error(f"Diagnosis failed: {str(e)}")
                self.after(0, lambda: self.update_status("Diagnosis failed"))
        
        threading.Thread(target=diagnosis_worker, daemon=True).start()
    
    def _show_diagnosis_results(self, results: Dict[str, Any]):
        """Show diagnosis results in UI"""
        output = []
        output.append("=== DEPENDENCY DIAGNOSIS RESULTS ===\n")
        
        # Python version
        py_info = results['python_version']
        status = "✅" if py_info['supported'] else "❌"
        output.append(f"{status} Python Version: {py_info['version']} ({'Supported' if py_info['supported'] else 'Unsupported'})")
        output.append(f"   Path: {py_info['path']}\n")
        
        # Missing packages
        missing = results['missing_packages']
        if missing:
            output.append(f"❌ Missing Packages ({len(missing)}):")
            for pkg in missing:
                output.append(f"   - {pkg}")
        else:
            output.append("✅ All required packages installed")
        output.append("")
        
        # Pip check
        pip_check = results['pip_check']
        if pip_check['success']:
            output.append("✅ No dependency conflicts detected")
        else:
            output.append("❌ Dependency conflicts found:")
            for issue in pip_check.get('issues', []):
                output.append(f"   - {issue}")
        output.append("")
        
        # Recommendations
        if results['recommendations']:
            output.append("💡 Recommendations:")
            for rec in results['recommendations']:
                output.append(f"   • {rec}")
        
        # Display results
        self.deps_results_text.delete("1.0", tk.END)
        self.deps_results_text.insert("1.0", "\n".join(output))
        self.update_status("Dependency diagnosis complete")
    
    def install_missing_dependencies(self):
        """Install missing dependencies"""
        def install_worker():
            try:
                missing = self.dependency_analyzer._check_missing_packages()
                if not missing:
                    self.after(0, lambda: messagebox.showinfo("Info", "No missing dependencies found"))
                    return
                
                self.after(0, lambda: self.update_status("Installing dependencies..."))
                success = self.dependency_analyzer.install_packages(
                    missing,
                    progress_callback=lambda msg: (self.after(0, lambda: self.update_status(msg)), None)[1]
                )
                
                if success:
                    self.after(0, lambda: self.update_status("Dependencies installed successfully"))
                    self.after(0, lambda: messagebox.showinfo("Success", "Dependencies installed successfully!"))
                else:
                    self.after(0, lambda: self.update_status("Dependency installation failed"))
                    self.after(0, lambda: messagebox.showerror("Error", "Failed to install dependencies"))
                    
            except Exception as e:
                self.logger.error(f"Installation failed: {str(e)}")
                self.after(0, lambda: messagebox.showerror("Error", f"Installation failed: {str(e)}"))
        
        threading.Thread(target=install_worker, daemon=True).start()
    
    def update_status(self, message: str):
        """Update status bar message"""
        self.status_label.configure(text=message)

# Create remaining UI tabs - simplified for completion
    def create_imports_tab(self):
        """Create imports management tab"""
        frame = ModernFrame(self.main_frame)
        self.tab_frames["Imports"] = frame
        
        # Title
        title_frame = ctk.CTkFrame(frame, fg_color="transparent")
        title_frame.pack(fill="x", padx=20, pady=(20, 10))
        
        ctk.CTkLabel(title_frame, text="Hidden Imports Management",
                    font=ctk.CTkFont(size=20, weight="bold")).pack(side="left")
        
        # Controls frame
        controls_frame = ctk.CTkFrame(frame, fg_color="transparent")
        controls_frame.pack(fill="x", padx=20, pady=10)
        
        # Detect imports button
        self.detect_imports_btn = ModernButton(
            controls_frame,
            text="Detect Imports",
            command=self.detect_imports,
            fg_color=COLORS['primary']
        )
        self.detect_imports_btn.pack(side="left", padx=5)
        
        # Add import button
        self.add_import_btn = ModernButton(
            controls_frame,
            text="Add Import",
            command=self.add_manual_import,
            fg_color=COLORS['secondary']
        )
        self.add_import_btn.pack(side="left", padx=5)
        
        # Remove selected button
        self.remove_import_btn = ModernButton(
            controls_frame,
            text="Remove Selected",
            command=self.remove_selected_imports,
            fg_color=COLORS['error']
        )
        self.remove_import_btn.pack(side="left", padx=5)
        
        # Clear all button
        self.clear_imports_btn = ModernButton(
            controls_frame,
            text="Clear All",
            command=self.clear_all_imports,
            fg_color=COLORS['warning']
        )
        self.clear_imports_btn.pack(side="left", padx=5)
        
        # Import lists frame
        lists_frame = ctk.CTkFrame(frame)
        lists_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Detected imports (left side)
        detected_frame = ctk.CTkFrame(lists_frame)
        detected_frame.pack(side="left", fill="both", expand=True, padx=(0, 5))
        
        ctk.CTkLabel(detected_frame, text="Detected Imports",
                    font=ctk.CTkFont(size=14, weight="bold")).pack(pady=5)
        
        # Detected imports listbox
        self.detected_imports_listbox = tk.Listbox(
            detected_frame,
            bg=COLORS['surface'],
            fg=COLORS['text'],
            selectbackground=COLORS['primary'],
            selectmode=tk.EXTENDED,
            font=('Consolas', 10)
        )
        self.detected_imports_listbox.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Scrollbar for detected imports
        detected_scrollbar = ttk.Scrollbar(self.detected_imports_listbox)
        detected_scrollbar.pack(side="right", fill="y")
        self.detected_imports_listbox.config(yscrollcommand=detected_scrollbar.set)
        detected_scrollbar.config(command=self.detected_imports_listbox.yview)
        
        # Hidden imports (right side)
        hidden_frame = ctk.CTkFrame(lists_frame)
        hidden_frame.pack(side="right", fill="both", expand=True, padx=(5, 0))
        
        ctk.CTkLabel(hidden_frame, text="Hidden Imports to Include",
                    font=ctk.CTkFont(size=14, weight="bold")).pack(pady=5)
        
        # Hidden imports listbox
        self.hidden_imports_listbox = tk.Listbox(
            hidden_frame,
            bg=COLORS['surface'],
            fg=COLORS['text'],
            selectbackground=COLORS['primary'],
            selectmode=tk.EXTENDED,
            font=('Consolas', 10)
        )
        self.hidden_imports_listbox.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Scrollbar for hidden imports
        hidden_scrollbar = ttk.Scrollbar(self.hidden_imports_listbox)
        hidden_scrollbar.pack(side="right", fill="y")
        self.hidden_imports_listbox.config(yscrollcommand=hidden_scrollbar.set)
        hidden_scrollbar.config(command=self.hidden_imports_listbox.yview)
        
        # Transfer buttons (middle)
        transfer_frame = ctk.CTkFrame(lists_frame, fg_color="transparent")
        transfer_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        # Add to hidden imports button
        self.add_to_hidden_btn = ModernButton(
            transfer_frame,
            text="→",
            width=40,
            command=self.transfer_to_hidden,
            fg_color=COLORS['success']
        )
        self.add_to_hidden_btn.pack(pady=5)
        
        # Remove from hidden imports button
        self.remove_from_hidden_btn = ModernButton(
            transfer_frame,
            text="←",
            width=40,
            command=self.transfer_from_hidden,
            fg_color=COLORS['warning']
        )
        self.remove_from_hidden_btn.pack(pady=5)
    
    def create_assets_tab(self):
        """Create assets management tab"""
        frame = ModernFrame(self.main_frame)
        self.tab_frames["Assets"] = frame
        
        # Title
        title_frame = ctk.CTkFrame(frame, fg_color="transparent")
        title_frame.pack(fill="x", padx=20, pady=(20, 10))
        
        ctk.CTkLabel(title_frame, text="Assets & Data Files",
                    font=ctk.CTkFont(size=20, weight="bold")).pack(side="left")
        
        # Controls frame
        controls_frame = ctk.CTkFrame(frame, fg_color="transparent")
        controls_frame.pack(fill="x", padx=20, pady=10)
        
        # Add file button
        self.add_file_btn = ModernButton(
            controls_frame,
            text="Add File",
            command=self.add_data_file,
            fg_color=COLORS['primary']
        )
        self.add_file_btn.pack(side="left", padx=5)
        
        # Add directory button
        self.add_dir_btn = ModernButton(
            controls_frame,
            text="Add Directory",
            command=self.add_data_directory,
            fg_color=COLORS['primary']
        )
        self.add_dir_btn.pack(side="left", padx=5)
        
        # Remove selected button
        self.remove_asset_btn = ModernButton(
            controls_frame,
            text="Remove Selected",
            command=self.remove_selected_assets,
            fg_color=COLORS['error']
        )
        self.remove_asset_btn.pack(side="left", padx=5)
        
        # Clear all button
        self.clear_assets_btn = ModernButton(
            controls_frame,
            text="Clear All",
            command=self.clear_all_assets,
            fg_color=COLORS['warning']
        )
        self.clear_assets_btn.pack(side="left", padx=5)
        
        # Assets table frame
        table_frame = ctk.CTkFrame(frame)
        table_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Create Treeview for assets
        columns = ('Source', 'Target', 'Type')
        self.assets_tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show='tree headings',
            selectmode='extended'
        )
        
        # Configure columns
        self.assets_tree.heading('#0', text='#', anchor='w')
        self.assets_tree.column('#0', width=50, stretch=False)
        
        self.assets_tree.heading('Source', text='Source Path', anchor='w')
        self.assets_tree.column('Source', width=400, stretch=True)
        
        self.assets_tree.heading('Target', text='Target Path', anchor='w')
        self.assets_tree.column('Target', width=300, stretch=True)
        
        self.assets_tree.heading('Type', text='Type', anchor='w')
        self.assets_tree.column('Type', width=100, stretch=False)
        
        # Style the treeview
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Treeview',
                       background=COLORS['surface'],
                       foreground=COLORS['text'],
                       fieldbackground=COLORS['surface'])
        style.configure('Treeview.Heading',
                       background=COLORS['surface_light'],
                       foreground=COLORS['text'])
        style.map('Treeview', background=[('selected', COLORS['primary'])])
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.assets_tree.yview)
        self.assets_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack treeview and scrollbar
        self.assets_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Info panel
        info_frame = ctk.CTkFrame(frame)
        info_frame.pack(fill="x", padx=20, pady=10)
        
        info_text = """📁 Add files and directories to include in your executable.
• Source Path: The file/directory on your system
• Target Path: Where it will be placed in the executable (relative path)
• Double-click to edit target paths"""
        
        ctk.CTkLabel(info_frame, text=info_text,
                    font=ctk.CTkFont(size=11),
                    justify="left").pack(padx=10, pady=10)
        
        # Bind double-click to edit
        self.assets_tree.bind('<Double-Button-1>', self.edit_asset_target)
    
    def create_installer_tab(self):
        """Create installer configuration tab"""
        frame = ModernFrame(self.main_frame)
        self.tab_frames["Installer"] = frame
        
        # Create scrollable frame
        scrollable_frame = ctk.CTkScrollableFrame(frame)
        scrollable_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Title
        ctk.CTkLabel(scrollable_frame, text="NSIS Installer Configuration",
                    font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(0, 20))
        
        # Basic Information Section
        basic_frame = ctk.CTkFrame(scrollable_frame)
        basic_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(basic_frame, text="Basic Information",
                    font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=5)
        
        # App Name
        app_name_frame = ctk.CTkFrame(basic_frame, fg_color="transparent")
        app_name_frame.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(app_name_frame, text="Application Name:", width=150).pack(side="left")
        self.installer_app_name = ctk.CTkEntry(app_name_frame, width=300)
        self.installer_app_name.pack(side="left", padx=10)
        
        # Version
        version_frame = ctk.CTkFrame(basic_frame, fg_color="transparent")
        version_frame.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(version_frame, text="Version:", width=150).pack(side="left")
        self.installer_version = ctk.CTkEntry(version_frame, width=300)
        self.installer_version.pack(side="left", padx=10)
        self.installer_version.insert(0, "1.0.0")
        
        # Company
        company_frame = ctk.CTkFrame(basic_frame, fg_color="transparent")
        company_frame.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(company_frame, text="Company Name:", width=150).pack(side="left")
        self.installer_company = ctk.CTkEntry(company_frame, width=300)
        self.installer_company.pack(side="left", padx=10)
        
        # Description
        desc_frame = ctk.CTkFrame(basic_frame, fg_color="transparent")
        desc_frame.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(desc_frame, text="Description:", width=150).pack(side="left")
        self.installer_description = ctk.CTkEntry(desc_frame, width=300)
        self.installer_description.pack(side="left", padx=10)
        
        # Installation Settings Section
        install_frame = ctk.CTkFrame(scrollable_frame)
        install_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(install_frame, text="Installation Settings",
                    font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=5)
        
        # Installation directory
        install_dir_frame = ctk.CTkFrame(install_frame, fg_color="transparent")
        install_dir_frame.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(install_dir_frame, text="Install Directory:", width=150).pack(side="left")
        self.installer_install_dir = ctk.CTkEntry(install_dir_frame, width=300)
        self.installer_install_dir.pack(side="left", padx=10)
        self.installer_install_dir.insert(0, "$PROGRAMFILES\\{app_name}")
        
        # Checkboxes
        checks_frame = ctk.CTkFrame(install_frame, fg_color="transparent")
        checks_frame.pack(fill="x", padx=20, pady=10)
        
        self.installer_desktop_shortcut = ctk.CTkCheckBox(
            checks_frame,
            text="Create Desktop Shortcut"
        )
        self.installer_desktop_shortcut.pack(side="left", padx=10)
        self.installer_desktop_shortcut.select()
        
        self.installer_start_menu = ctk.CTkCheckBox(
            checks_frame,
            text="Create Start Menu Entry"
        )
        self.installer_start_menu.pack(side="left", padx=10)
        self.installer_start_menu.select()
        
        self.installer_per_user = ctk.CTkCheckBox(
            checks_frame,
            text="Per-User Installation"
        )
        self.installer_per_user.pack(side="left", padx=10)
        
        self.installer_silent_mode = ctk.CTkCheckBox(
            checks_frame,
            text="Silent Mode"
        )
        self.installer_silent_mode.pack(side="left", padx=10)
        
        # Additional Files Section
        files_frame = ctk.CTkFrame(scrollable_frame)
        files_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(files_frame, text="Additional Files",
                    font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=5)
        
        # EULA file
        eula_frame = ctk.CTkFrame(files_frame, fg_color="transparent")
        eula_frame.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(eula_frame, text="EULA File:", width=150).pack(side="left")
        self.installer_eula_file = ctk.CTkEntry(eula_frame, width=250)
        self.installer_eula_file.pack(side="left", padx=10)
        ModernButton(
            eula_frame,
            text="Browse",
            width=70,
            command=lambda: self.browse_file_for_entry(self.installer_eula_file, "Select EULA File", [("Text files", "*.txt;*.rtf")])
        ).pack(side="left")
        
        # Banner image
        banner_frame = ctk.CTkFrame(files_frame, fg_color="transparent")
        banner_frame.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(banner_frame, text="Banner Image:", width=150).pack(side="left")
        self.installer_banner_image = ctk.CTkEntry(banner_frame, width=250)
        self.installer_banner_image.pack(side="left", padx=10)
        ModernButton(
            banner_frame,
            text="Browse",
            width=70,
            command=lambda: self.browse_file_for_entry(self.installer_banner_image, "Select Banner Image", [("Image files", "*.bmp;*.jpg;*.jpeg;*.png")])
        ).pack(side="left")
        
        # Output Settings Section
        output_frame = ctk.CTkFrame(scrollable_frame)
        output_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(output_frame, text="Output Settings",
                    font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=5)
        
        # Output directory
        output_dir_frame = ctk.CTkFrame(output_frame, fg_color="transparent")
        output_dir_frame.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(output_dir_frame, text="Output Directory:", width=150).pack(side="left")
        self.installer_output_dir = ctk.CTkEntry(output_dir_frame, width=250)
        self.installer_output_dir.pack(side="left", padx=10)
        self.installer_output_dir.insert(0, "./installer")
        ModernButton(
            output_dir_frame,
            text="Browse",
            width=70,
            command=lambda: self.browse_directory_for_entry(self.installer_output_dir, "Select Output Directory")
        ).pack(side="left")
        
        # Build button
        build_frame = ctk.CTkFrame(scrollable_frame, fg_color="transparent")
        build_frame.pack(fill="x", pady=20)
        
        self.build_installer_btn = ModernButton(
            build_frame,
            text="Build NSIS Installer",
            command=self.build_nsis_installer,
            fg_color=COLORS['success'],
            width=200,
            height=40
        )
        self.build_installer_btn.pack()
        
        # Status label
        self.installer_status_label = ctk.CTkLabel(
            build_frame,
            text="",
            font=ctk.CTkFont(size=12)
        )
        self.installer_status_label.pack(pady=10)
    
    def create_settings_tab(self):
        """Create settings tab"""
        frame = ModernFrame(self.main_frame)
        self.tab_frames["Settings"] = frame
        
        # Create scrollable frame
        scrollable_frame = ctk.CTkScrollableFrame(frame)
        scrollable_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Title
        ctk.CTkLabel(scrollable_frame, text="Application Settings",
                    font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(0, 20))
        
        # Appearance Section
        appearance_frame = ctk.CTkFrame(scrollable_frame)
        appearance_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(appearance_frame, text="Appearance",
                    font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=5)
        
        # Theme selection
        theme_frame = ctk.CTkFrame(appearance_frame, fg_color="transparent")
        theme_frame.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(theme_frame, text="Theme:", width=150).pack(side="left")
        self.theme_var = ctk.StringVar(value="dark")
        self.theme_menu = ctk.CTkOptionMenu(
            theme_frame,
            values=["dark", "light", "system"],
            variable=self.theme_var,
            command=self.change_theme,
            width=200
        )
        self.theme_menu.pack(side="left", padx=10)
        
        # Color scheme selection
        color_frame = ctk.CTkFrame(appearance_frame, fg_color="transparent")
        color_frame.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(color_frame, text="Color Scheme:", width=150).pack(side="left")
        self.color_var = ctk.StringVar(value="blue")
        self.color_menu = ctk.CTkOptionMenu(
            color_frame,
            values=["blue", "green", "dark-blue"],
            variable=self.color_var,
            command=self.change_color_theme,
            width=200
        )
        self.color_menu.pack(side="left", padx=10)
        
        # UI Scale
        scale_frame = ctk.CTkFrame(appearance_frame, fg_color="transparent")
        scale_frame.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(scale_frame, text="UI Scale:", width=150).pack(side="left")
        self.ui_scale_var = ctk.StringVar(value="100%")
        self.ui_scale_menu = ctk.CTkOptionMenu(
            scale_frame,
            values=["75%", "100%", "125%", "150%"],
            variable=self.ui_scale_var,
            command=self.change_ui_scale,
            width=200
        )
        self.ui_scale_menu.pack(side="left", padx=10)
        
        # Logging Section
        logging_frame = ctk.CTkFrame(scrollable_frame)
        logging_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(logging_frame, text="Logging",
                    font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=5)
        
        # Log retention
        log_size_frame = ctk.CTkFrame(logging_frame, fg_color="transparent")
        log_size_frame.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(log_size_frame, text="Max Log Size (MB):", width=150).pack(side="left")
        self.log_max_size = ctk.CTkEntry(log_size_frame, width=100)
        self.log_max_size.pack(side="left", padx=10)
        self.log_max_size.insert(0, "10")
        
        log_files_frame = ctk.CTkFrame(logging_frame, fg_color="transparent")
        log_files_frame.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(log_files_frame, text="Max Log Files:", width=150).pack(side="left")
        self.log_max_files = ctk.CTkEntry(log_files_frame, width=100)
        self.log_max_files.pack(side="left", padx=10)
        self.log_max_files.insert(0, "5")
        
        # Log level
        log_level_frame = ctk.CTkFrame(logging_frame, fg_color="transparent")
        log_level_frame.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(log_level_frame, text="Default Log Level:", width=150).pack(side="left")
        self.log_level_var = ctk.StringVar(value="INFO")
        self.log_level_menu = ctk.CTkOptionMenu(
            log_level_frame,
            values=["DEBUG", "INFO", "WARNING", "ERROR"],
            variable=self.log_level_var,
            width=200
        )
        self.log_level_menu.pack(side="left", padx=10)
        
        # Build Settings Section
        build_frame = ctk.CTkFrame(scrollable_frame)
        build_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(build_frame, text="Build Settings",
                    font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=5)
        
        # Default output directory
        output_dir_frame = ctk.CTkFrame(build_frame, fg_color="transparent")
        output_dir_frame.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(output_dir_frame, text="Default Output Dir:", width=150).pack(side="left")
        self.default_output_dir = ctk.CTkEntry(output_dir_frame, width=250)
        self.default_output_dir.pack(side="left", padx=10)
        self.default_output_dir.insert(0, "./dist")
        ModernButton(
            output_dir_frame,
            text="Browse",
            width=70,
            command=lambda: self.browse_directory_for_entry(self.default_output_dir, "Select Default Output Directory")
        ).pack(side="left")
        
        # Cache directory
        cache_dir_frame = ctk.CTkFrame(build_frame, fg_color="transparent")
        cache_dir_frame.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(cache_dir_frame, text="Cache Directory:", width=150).pack(side="left")
        self.cache_dir_entry = ctk.CTkEntry(cache_dir_frame, width=250)
        self.cache_dir_entry.pack(side="left", padx=10)
        self.cache_dir_entry.insert(0, str(CACHE_DIR))
        ModernButton(
            cache_dir_frame,
            text="Browse",
            width=70,
            command=lambda: self.browse_directory_for_entry(self.cache_dir_entry, "Select Cache Directory")
        ).pack(side="left")
        
        # Code Signing Section
        signing_frame = ctk.CTkFrame(scrollable_frame)
        signing_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(signing_frame, text="Code Signing",
                    font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=5)
        
        # Enable code signing
        self.enable_signing = ctk.CTkCheckBox(
            signing_frame,
            text="Enable Code Signing",
            command=self.toggle_signing_options
        )
        self.enable_signing.pack(anchor="w", padx=20, pady=5)
        
        # Certificate path
        cert_frame = ctk.CTkFrame(signing_frame, fg_color="transparent")
        cert_frame.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(cert_frame, text="Certificate Path:", width=150).pack(side="left")
        self.cert_path_entry = ctk.CTkEntry(cert_frame, width=250, state="disabled")
        self.cert_path_entry.pack(side="left", padx=10)
        self.cert_browse_btn = ModernButton(
            cert_frame,
            text="Browse",
            width=70,
            command=lambda: self.browse_file_for_entry(self.cert_path_entry, "Select Certificate", [("Certificate files", "*.pfx;*.p12")]),
            state="disabled"
        )
        self.cert_browse_btn.pack(side="left")
        
        # Certificate password
        cert_pass_frame = ctk.CTkFrame(signing_frame, fg_color="transparent")
        cert_pass_frame.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(cert_pass_frame, text="Certificate Password:", width=150).pack(side="left")
        self.cert_password_entry = ctk.CTkEntry(cert_pass_frame, width=250, show="*", state="disabled")
        self.cert_password_entry.pack(side="left", padx=10)
        
        # Timestamp server
        timestamp_frame = ctk.CTkFrame(signing_frame, fg_color="transparent")
        timestamp_frame.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(timestamp_frame, text="Timestamp Server:", width=150).pack(side="left")
        self.timestamp_server_var = ctk.StringVar(value="http://timestamp.digicert.com")
        self.timestamp_server_menu = ctk.CTkOptionMenu(
            timestamp_frame,
            values=[
                "http://timestamp.digicert.com",
                "http://timestamp.sectigo.com",
                "http://timestamp.comodoca.com",
                "http://sha256timestamp.ws.symantec.com/sha256/timestamp"
            ],
            variable=self.timestamp_server_var,
            width=350,
            state="disabled"
        )
        self.timestamp_server_menu.pack(side="left", padx=10)
        
        # Advanced Section
        advanced_frame = ctk.CTkFrame(scrollable_frame)
        advanced_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(advanced_frame, text="Advanced",
                    font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=5)
        
        # Auto-update check
        self.auto_update_check = ctk.CTkCheckBox(
            advanced_frame,
            text="Check for updates on startup"
        )
        self.auto_update_check.pack(anchor="w", padx=20, pady=5)
        self.auto_update_check.select()
        
        # Enable telemetry
        self.enable_telemetry = ctk.CTkCheckBox(
            advanced_frame,
            text="Send anonymous usage statistics"
        )
        self.enable_telemetry.pack(anchor="w", padx=20, pady=5)
        
        # Clear cache button
        cache_btn_frame = ctk.CTkFrame(advanced_frame, fg_color="transparent")
        cache_btn_frame.pack(fill="x", padx=20, pady=10)
        
        ModernButton(
            cache_btn_frame,
            text="Clear Cache",
            command=self.clear_cache,
            fg_color=COLORS['warning'],
            width=120
        ).pack(side="left", padx=5)
        
        ModernButton(
            cache_btn_frame,
            text="Reset to Defaults",
            command=self.reset_settings,
            fg_color=COLORS['error'],
            width=120
        ).pack(side="left", padx=5)
        
        # Save/Apply buttons
        button_frame = ctk.CTkFrame(scrollable_frame, fg_color="transparent")
        button_frame.pack(fill="x", pady=20)
        
        ModernButton(
            button_frame,
            text="Save Settings",
            command=self.save_settings,
            fg_color=COLORS['success'],
            width=150,
            height=40
        ).pack(side="left", padx=10)
        
        ModernButton(
            button_frame,
            text="Apply",
            command=self.apply_settings,
            fg_color=COLORS['primary'],
            width=150,
            height=40
        ).pack(side="left", padx=10)
        
        # Load current settings
        self.load_settings()
    
    def create_json_tab(self):
        """Create JSON tools tab"""
        frame = ModernFrame(self.main_frame)
        self.tab_frames["JSON Tools"] = frame
        
        # Title
        title_frame = ctk.CTkFrame(frame, fg_color="transparent")
        title_frame.pack(fill="x", padx=20, pady=(20, 10))
        
        ctk.CTkLabel(title_frame, text="JSON Configuration Tools",
                    font=ctk.CTkFont(size=20, weight="bold")).pack(side="left")
        
        # Controls frame
        controls_frame = ctk.CTkFrame(frame, fg_color="transparent")
        controls_frame.pack(fill="x", padx=20, pady=10)
        
        # Import JSON button
        self.import_json_btn = ModernButton(
            controls_frame,
            text="Import JSON",
            command=self.import_json_config,
            fg_color=COLORS['primary']
        )
        self.import_json_btn.pack(side="left", padx=5)
        
        # Export JSON button
        self.export_json_btn = ModernButton(
            controls_frame,
            text="Export JSON",
            command=self.export_json_config,
            fg_color=COLORS['success']
        )
        self.export_json_btn.pack(side="left", padx=5)
        
        # Validate JSON button
        self.validate_json_btn = ModernButton(
            controls_frame,
            text="Validate",
            command=self.validate_json,
            fg_color=COLORS['warning']
        )
        self.validate_json_btn.pack(side="left", padx=5)
        
        # Format JSON button
        self.format_json_btn = ModernButton(
            controls_frame,
            text="Format",
            command=self.format_json,
            fg_color=COLORS['secondary']
        )
        self.format_json_btn.pack(side="left", padx=5)
        
        # Template dropdown
        template_frame = ctk.CTkFrame(controls_frame, fg_color="transparent")
        template_frame.pack(side="right", padx=10)
        
        ctk.CTkLabel(template_frame, text="Template:").pack(side="left", padx=5)
        self.template_var = ctk.StringVar(value="Select Template")
        self.template_menu = ctk.CTkOptionMenu(
            template_frame,
            values=["CLI Application", "GUI Application", "Web Service", "Data Science", "Game", "Custom"],
            variable=self.template_var,
            command=self.load_template,
            width=150
        )
        self.template_menu.pack(side="left")
        
        # Main content area with JSON editor and preview
        content_frame = ctk.CTkFrame(frame)
        content_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # JSON Editor (left side)
        editor_frame = ctk.CTkFrame(content_frame)
        editor_frame.pack(side="left", fill="both", expand=True, padx=(0, 5))
        
        editor_label = ctk.CTkLabel(editor_frame, text="JSON Editor",
                                   font=ctk.CTkFont(size=14, weight="bold"))
        editor_label.pack(pady=5)
        
        # JSON text editor
        self.json_editor = tk.Text(
            editor_frame,
            bg=COLORS['surface'],
            fg=COLORS['text'],
            insertbackground=COLORS['text'],
            selectbackground=COLORS['primary'],
            font=('Consolas', 11),
            wrap=tk.WORD,
            undo=True
        )
        self.json_editor.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Add syntax highlighting tags
        self.json_editor.tag_config("keyword", foreground="#569cd6")
        self.json_editor.tag_config("string", foreground="#ce9178")
        self.json_editor.tag_config("number", foreground="#b5cea8")
        self.json_editor.tag_config("boolean", foreground="#569cd6")
        self.json_editor.tag_config("null", foreground="#569cd6")
        self.json_editor.tag_config("error", foreground="#f44747", underline=True)
        
        # Scrollbar for editor
        editor_scrollbar = ttk.Scrollbar(self.json_editor)
        editor_scrollbar.pack(side="right", fill="y")
        self.json_editor.config(yscrollcommand=editor_scrollbar.set)
        editor_scrollbar.config(command=self.json_editor.yview)
        
        # Preview/Tree View (right side)
        preview_frame = ctk.CTkFrame(content_frame)
        preview_frame.pack(side="right", fill="both", expand=True, padx=(5, 0))
        
        preview_label = ctk.CTkLabel(preview_frame, text="Configuration Preview",
                                    font=ctk.CTkFont(size=14, weight="bold"))
        preview_label.pack(pady=5)
        
        # Tree view for JSON structure
        self.json_tree = ttk.Treeview(
            preview_frame,
            columns=('Value', 'Type'),
            show='tree headings',
            selectmode='browse'
        )
        
        # Configure columns
        self.json_tree.heading('#0', text='Key', anchor='w')
        self.json_tree.column('#0', width=200, stretch=True)
        
        self.json_tree.heading('Value', text='Value', anchor='w')
        self.json_tree.column('Value', width=250, stretch=True)
        
        self.json_tree.heading('Type', text='Type', anchor='w')
        self.json_tree.column('Type', width=100, stretch=False)
        
        # Style the treeview
        style = ttk.Style()
        style.configure('JSON.Treeview',
                       background=COLORS['surface'],
                       foreground=COLORS['text'],
                       fieldbackground=COLORS['surface'])
        self.json_tree.configure(style='JSON.Treeview')
        
        # Scrollbar for tree
        tree_scrollbar = ttk.Scrollbar(preview_frame, orient="vertical", command=self.json_tree.yview)
        self.json_tree.configure(yscrollcommand=tree_scrollbar.set)
        
        self.json_tree.pack(side="left", fill="both", expand=True, padx=10, pady=5)
        tree_scrollbar.pack(side="right", fill="y")
        
        # Status bar
        status_frame = ctk.CTkFrame(frame)
        status_frame.pack(fill="x", padx=20, pady=10)
        
        self.json_status_label = ctk.CTkLabel(
            status_frame,
            text="Ready",
            font=ctk.CTkFont(size=11),
            anchor="w"
        )
        self.json_status_label.pack(side="left", padx=10)
        
        # Bind events
        self.json_editor.bind('<KeyRelease>', self.on_json_change)
        self.json_editor.bind('<Control-s>', lambda e: self.export_json_config())
        self.json_editor.bind('<Control-o>', lambda e: self.import_json_config())
        
        # Load current configuration into editor
        self.load_current_config_to_json()
    
    # ============= Imports Tab Methods =============
    def detect_imports(self):
        """Detect hidden imports in the current script"""
        if not self.current_config.build.script_path:
            messagebox.showwarning("No Script", "Please select a Python script first.")
            return
        
        self.log_message("Detecting imports...", "INFO")
        
        def run_detection():
            try:
                imports = self.import_detector.detect_imports(self.current_config.build.script_path)
                
                # Update UI in main thread
                self.after(0, lambda: self.update_detected_imports(imports))
                self.after(0, lambda: self.log_message(f"Detected {len(imports['static'])} static and {len(imports['dynamic'])} dynamic imports", "SUCCESS"))
            except Exception as e:
                self.after(0, lambda: self.log_message(f"Import detection failed: {e}", "ERROR"))
        
        threading.Thread(target=run_detection, daemon=True).start()
    
    def update_detected_imports(self, imports):
        """Update the detected imports listbox"""
        self.detected_imports_listbox.delete(0, tk.END)
        
        # Add static imports
        for imp in sorted(imports['static']):
            self.detected_imports_listbox.insert(tk.END, f"[S] {imp}")
        
        # Add dynamic imports
        for imp in sorted(imports['dynamic']):
            self.detected_imports_listbox.insert(tk.END, f"[D] {imp}")
    
    def add_manual_import(self):
        """Add a manual import"""
        dialog = ctk.CTkInputDialog(
            text="Enter module name to add:",
            title="Add Import"
        )
        module_name = dialog.get_input()
        
        if module_name:
            self.hidden_imports_listbox.insert(tk.END, module_name)
            self.current_config.build.hidden_imports.append(module_name)
            self.log_message(f"Added import: {module_name}", "INFO")
    
    def remove_selected_imports(self):
        """Remove selected imports from hidden imports list"""
        selections = self.hidden_imports_listbox.curselection()
        
        for index in reversed(selections):
            item = self.hidden_imports_listbox.get(index)
            self.hidden_imports_listbox.delete(index)
            
            # Remove from config
            clean_item = item.replace("[S] ", "").replace("[D] ", "")
            if clean_item in self.current_config.build.hidden_imports:
                self.current_config.build.hidden_imports.remove(clean_item)
    
    def clear_all_imports(self):
        """Clear all hidden imports"""
        if messagebox.askyesno("Clear Imports", "Remove all hidden imports?"):
            self.hidden_imports_listbox.delete(0, tk.END)
            self.current_config.build.hidden_imports.clear()
            self.log_message("Cleared all hidden imports", "INFO")
    
    def transfer_to_hidden(self):
        """Transfer selected detected imports to hidden imports list"""
        selections = self.detected_imports_listbox.curselection()
        
        for index in selections:
            item = self.detected_imports_listbox.get(index)
            clean_item = item.replace("[S] ", "").replace("[D] ", "")
            
            # Add to hidden imports if not already there
            if clean_item not in self.current_config.build.hidden_imports:
                self.hidden_imports_listbox.insert(tk.END, clean_item)
                self.current_config.build.hidden_imports.append(clean_item)
    
    def transfer_from_hidden(self):
        """Remove selected items from hidden imports"""
        self.remove_selected_imports()
    
    # ============= Assets Tab Methods =============
    def add_data_file(self):
        """Add a data file to the build"""
        file_path = filedialog.askopenfilename(
            title="Select Data File",
            parent=self
        )
        
        if file_path:
            # Ask for target path
            dialog = ctk.CTkInputDialog(
                text="Enter target path (relative to executable):",
                title="Target Path"
            )
            target = dialog.get_input()
            
            if not target:
                target = Path(file_path).name
            
            # Add to tree and config
            self.assets_tree.insert(
                '',
                'end',
                text=str(len(self.current_config.build.data_paths) + 1),
                values=(file_path, target, 'File')
            )
            
            self.current_config.build.data_paths.append((file_path, target))
            self.log_message(f"Added data file: {Path(file_path).name}", "INFO")
    
    def add_data_directory(self):
        """Add a data directory to the build"""
        dir_path = filedialog.askdirectory(
            title="Select Data Directory",
            parent=self
        )
        
        if dir_path:
            # Ask for target path
            dialog = ctk.CTkInputDialog(
                text="Enter target path (relative to executable):",
                title="Target Path"
            )
            target = dialog.get_input()
            
            if not target:
                target = Path(dir_path).name
            
            # Add to tree and config
            _ = self.assets_tree.insert(
                '',
                'end',
                text=str(len(self.current_config.build.data_paths) + 1),
                values=(dir_path, target, 'Directory')
            )
            
            self.current_config.build.data_paths.append((dir_path, target))
            self.log_message(f"Added data directory: {Path(dir_path).name}", "INFO")
    
    def remove_selected_assets(self):
        """Remove selected assets from the list"""
        selections = self.assets_tree.selection()
        
        if not selections:
            return
        
        # Get indices to remove
        indices_to_remove = []
        for item in selections:
            index = int(self.assets_tree.item(item)['text']) - 1
            indices_to_remove.append(index)
        
        # Remove from config (in reverse order to maintain indices)
        for index in sorted(indices_to_remove, reverse=True):
            if 0 <= index < len(self.current_config.build.data_paths):
                del self.current_config.build.data_paths[index]
        
        # Remove from tree
        for item in selections:
            self.assets_tree.delete(item)
        
        # Renumber items
        for i, item in enumerate(self.assets_tree.get_children()):
            self.assets_tree.item(item, text=str(i + 1))
    
    def clear_all_assets(self):
        """Clear all assets"""
        if messagebox.askyesno("Clear Assets", "Remove all data files and directories?"):
            self.assets_tree.delete(*self.assets_tree.get_children())
            self.current_config.build.data_paths.clear()
            self.log_message("Cleared all assets", "INFO")
    
    def edit_asset_target(self, _event=None):
        """Edit the target path of an asset"""
        selection = self.assets_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        values = self.assets_tree.item(item)['values']
        
        dialog = ctk.CTkInputDialog(
            text=f"Edit target path for:\n{values[0]}",
            title="Edit Target Path"
        )
        dialog._entry.insert(0, values[1])
        new_target = dialog.get_input()
        
        if new_target and new_target != values[1]:
            # Update tree
            self.assets_tree.item(item, values=(values[0], new_target, values[2]))
            
            # Update config
            index = int(self.assets_tree.item(item)['text']) - 1
            if 0 <= index < len(self.current_config.build.data_paths):
                source, _ = self.current_config.build.data_paths[index]
                self.current_config.build.data_paths[index] = (source, new_target)
    
    # ============= Installer Tab Methods =============
    def build_nsis_installer(self):
        """Build NSIS installer"""
        # Validate inputs
        if not self.installer_app_name.get():
            messagebox.showerror("Error", "Please enter an application name")
            return
        
        if not self.current_config.build.exe_name:
            messagebox.showerror("Error", "Please build the executable first")
            return
        
        # Create installer config
        installer_config = InstallerConfig(
            app_name=self.installer_app_name.get(),
            version=self.installer_version.get() or "1.0.0",
            company=self.installer_company.get() or "",
            description=self.installer_description.get() or "",
            output_dir=self.installer_output_dir.get() or "./installer",
            desktop_shortcut=bool(self.installer_desktop_shortcut.get()),
            start_menu=bool(self.installer_start_menu.get()),
            install_dir=self.installer_install_dir.get().replace("{app_name}", self.installer_app_name.get()),
            per_user=bool(self.installer_per_user.get()),
            eula_file=self.installer_eula_file.get() or None,  # Convert empty string to None
            banner_image=self.installer_banner_image.get() or None,  # Convert empty string to None
            silent_mode=bool(self.installer_silent_mode.get())
        )
        
        # Update status
        self.installer_status_label.configure(text="Building installer...", text_color=COLORS['warning'])
        self.build_installer_btn.configure(state="disabled")
        
        def build_installer():
            try:
                # Build the installer
                exe_path = Path(self.current_config.build.output_dir) / f"{self.current_config.build.exe_name}.exe"
                installer_path = self.nsis_installer.build_installer(
                    exe_path=str(exe_path),
                    config=installer_config,
                    signing_config=self.current_config.signing if self.enable_signing.get() else None
                )
                
                # Update UI in main thread
                self.after(0, lambda: self.installer_status_label.configure(
                    text=f"✓ Installer created: {installer_path}",
                    text_color=COLORS['success']
                ))
                self.after(0, lambda: self.log_message(f"Installer created successfully: {installer_path}", "SUCCESS"))
            except Exception as e:
                self.after(0, lambda: self.installer_status_label.configure(
                    text=f"✗ Build failed: {str(e)}",
                    text_color=COLORS['error']
                ))
                self.after(0, lambda: self.log_message(f"Installer build failed: {e}", "ERROR"))
            finally:
                self.after(0, lambda: self.build_installer_btn.configure(state="normal"))
        
        threading.Thread(target=build_installer, daemon=True).start()
    
    def browse_file_for_entry(self, entry_widget, title, filetypes):
        """Browse for a file and update entry widget"""
        file_path = filedialog.askopenfilename(
            title=title,
            filetypes=filetypes,
            parent=self
        )
        
        if file_path:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, file_path)
    
    def browse_directory_for_entry(self, entry_widget, title):
        """Browse for a directory and update entry widget"""
        dir_path = filedialog.askdirectory(
            title=title,
            parent=self
        )
        
        if dir_path:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, dir_path)

    def browse_icon(self):
        """Browse for an icon file and update the icon entry widget"""
        file_path = filedialog.askopenfilename(
            title="Select Icon",
            filetypes=[("Icon files", "*.ico;*.png;*.icns"), ("All files", "*")],
            parent=self
        )

        if file_path:
            try:
                self.icon_entry.delete(0, tk.END)
                self.icon_entry.insert(0, file_path)
            except Exception:
                # Guard against missing widget during headless/static analysis
                self.logger.debug("icon_entry not present to update")
    
    # ============= Settings Tab Methods =============
    def change_theme(self, theme):
        """Change application theme"""
        ctk.set_appearance_mode(theme)
        self.log_message(f"Theme changed to: {theme}", "INFO")
    
    def change_color_theme(self, color: str):
        """Change color theme"""
        ctk.set_default_color_theme(color)
        self.log_message(f"Color theme changed to: {color}", "INFO")
    
    def change_ui_scale(self, scale):
        """Change UI scale"""
        scale_value = float(scale.replace("%", "")) / 100
        ctk.set_widget_scaling(scale_value)
        ctk.set_window_scaling(scale_value)
        self.log_message(f"UI scale changed to: {scale}", "INFO")
    
    def toggle_signing_options(self):
        """Enable/disable signing-related fields"""
        state = "normal" if self.enable_signing.get() else "disabled"
        
        self.cert_path_entry.configure(state=state)
        self.cert_browse_btn.configure(state=state)
        self.cert_password_entry.configure(state=state)
        self.timestamp_server_menu.configure(state=state)
    
    def clear_cache(self):
        """Clear application cache"""
        if messagebox.askyesno("Clear Cache", "This will remove all cached data. Continue?"):
            try:
                if CACHE_DIR.exists():
                    shutil.rmtree(CACHE_DIR)
                    CACHE_DIR.mkdir(parents=True, exist_ok=True)
                self.log_message("Cache cleared successfully", "SUCCESS")
                messagebox.showinfo("Success", "Cache cleared successfully")
            except Exception as e:
                self.log_message(f"Failed to clear cache: {e}", "ERROR")
                messagebox.showerror("Error", f"Failed to clear cache: {e}")
    
    def reset_settings(self):
        """Reset all settings to defaults"""
        if messagebox.askyesno("Reset Settings", "This will reset all settings to defaults. Continue?"):
            # Reset UI elements
            self.theme_var.set("dark")
            self.ui_scale_var.set("100%")
            self.log_max_size.delete(0, tk.END)
            self.log_max_size.insert(0, "10")
            self.log_max_files.delete(0, tk.END)
            self.log_max_files.insert(0, "5")
            self.log_level_var.set("INFO")
            self.default_output_dir.delete(0, tk.END)
            self.default_output_dir.insert(0, "./dist")
            self.cache_dir_entry.delete(0, tk.END)
            self.cache_dir_entry.insert(0, str(CACHE_DIR))
            self.enable_signing.deselect()
            self.auto_update_check.select()
            self.enable_telemetry.deselect()
            
            # Apply changes
            self.apply_settings()
            self.log_message("Settings reset to defaults", "INFO")
    
    def save_settings(self):
        """Save settings to configuration file"""
        settings = {
            "appearance": {
                "theme": self.theme_var.get(),
                "ui_scale": self.ui_scale_var.get()
            },
            "logging": {
                "max_size_mb": int(self.log_max_size.get() or 10),
                "max_files": int(self.log_max_files.get() or 5),
                "default_level": self.log_level_var.get()
            },
            "build": {
                "default_output_dir": self.default_output_dir.get(),
                "cache_dir": self.cache_dir_entry.get()
            },
            "signing": {
                "enabled": self.enable_signing.get(),
                "cert_path": self.cert_path_entry.get() if self.enable_signing.get() else "",
                "timestamp_server": self.timestamp_server_var.get()
            },
            "advanced": {
                "auto_update": self.auto_update_check.get(),
                "telemetry": self.enable_telemetry.get()
            }
        }
        
        # Save to file
        settings_file = CONFIG_DIR / "settings.json"
        try:
            with open(settings_file, 'w') as f:
                json.dump(settings, f, indent=2)
            
            # Store password securely if provided
            if self.enable_signing.get() and self.cert_password_entry.get():
                self.secure_storage.store_password("cert_password", self.cert_password_entry.get())
            
            self.log_message("Settings saved successfully", "SUCCESS")
            messagebox.showinfo("Success", "Settings saved successfully")
        except Exception as e:
            self.log_message(f"Failed to save settings: {e}", "ERROR")
            messagebox.showerror("Error", f"Failed to save settings: {e}")
    
    def apply_settings(self):
        """Apply current settings without saving"""
        # Apply theme
        self.change_theme(self.theme_var.get())
        
        # Apply UI scale
        self.change_ui_scale(self.ui_scale_var.get())
        
        # Update logger settings
        if hasattr(self, 'logger'):
            self.logger.max_size = int(self.log_max_size.get() or 10) * 1024 * 1024
            self.logger.max_files = int(self.log_max_files.get() or 5)
        
        # Update build config
        self.current_config.build.output_dir = self.default_output_dir.get()
        
        # Update signing config if enabled
        if self.enable_signing.get():
            self.current_config.signing = SigningConfig(
                cert_path=self.cert_path_entry.get(),
                cert_password="",  # Retrieved from secure storage when needed
                timestamp_server=self.timestamp_server_var.get()
            )
        else:
            self.current_config.signing = None
        
        self.log_message("Settings applied", "INFO")
    
    def load_settings(self):
        """Load settings from configuration file"""
        settings_file = CONFIG_DIR / "settings.json"
        
        if not settings_file.exists():
            return
        
        try:
            with open(settings_file, 'r') as f:
                settings = json.load(f)
            
            # Apply appearance settings
            if "appearance" in settings:
                self.theme_var.set(settings["appearance"].get("theme", "dark"))
                self.ui_scale_var.set(settings["appearance"].get("ui_scale", "100%"))
            
            # Apply logging settings
            if "logging" in settings:
                self.log_max_size.delete(0, tk.END)
                self.log_max_size.insert(0, str(settings["logging"].get("max_size_mb", 10)))
                self.log_max_files.delete(0, tk.END)
                self.log_max_files.insert(0, str(settings["logging"].get("max_files", 5)))
                self.log_level_var.set(settings["logging"].get("default_level", "INFO"))
            
            # Apply build settings
            if "build" in settings:
                self.default_output_dir.delete(0, tk.END)
                self.default_output_dir.insert(0, settings["build"].get("default_output_dir", "./dist"))
                self.cache_dir_entry.delete(0, tk.END)
                self.cache_dir_entry.insert(0, settings["build"].get("cache_dir", str(CACHE_DIR)))
            
            # Apply signing settings
            if "signing" in settings:
                if settings["signing"].get("enabled"):
                    self.enable_signing.select()
                    self.cert_path_entry.configure(state="normal")
                    self.cert_path_entry.delete(0, tk.END)
                    self.cert_path_entry.insert(0, settings["signing"].get("cert_path", ""))
                    self.timestamp_server_var.set(settings["signing"].get("timestamp_server", "http://timestamp.digicert.com"))
                    
                    # Try to retrieve password from secure storage
                    try:
                        password = self.secure_storage.get_password("cert_password")
                        if password:
                            self.cert_password_entry.configure(state="normal")
                            self.cert_password_entry.delete(0, tk.END)
                            self.cert_password_entry.insert(0, password)
                    except:
                        pass
            
            # Apply advanced settings
            if "advanced" in settings:
                if settings["advanced"].get("auto_update"):
                    self.auto_update_check.select()
                else:
                    self.auto_update_check.deselect()
                
                if settings["advanced"].get("telemetry"):
                    self.enable_telemetry.select()
                else:
                    self.enable_telemetry.deselect()
            
            # Apply settings
            self.apply_settings()
            
        except Exception as e:
            self.log_message(f"Failed to load settings: {e}", "WARNING")
    
    # ============= JSON Tools Tab Methods =============
    def import_json_config(self):
        """Import JSON configuration from file"""
        file_path = filedialog.askopenfilename(
            title="Import JSON Configuration",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            parent=self
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    json_content = f.read()
                
                # Validate JSON
                config_dict = json.loads(json_content)
                
                # Load into editor
                self.json_editor.delete(1.0, tk.END)
                self.json_editor.insert(1.0, json.dumps(config_dict, indent=2))
                
                # Update tree view
                self.update_json_tree(config_dict)
                
                # Update current config
                self.current_config = ProjectConfig.from_dict(config_dict)
                
                self.json_status_label.configure(text=f"✓ Imported: {Path(file_path).name}")
                self.log_message(f"Imported configuration from {file_path}", "SUCCESS")
            except json.JSONDecodeError as e:
                self.json_status_label.configure(text=f"✗ Invalid JSON: {e}")
                messagebox.showerror("Import Error", f"Invalid JSON: {e}")
            except Exception as e:
                self.json_status_label.configure(text=f"✗ Import failed: {e}")
                messagebox.showerror("Import Error", f"Failed to import: {e}")
    
    def export_json_config(self):
        """Export JSON configuration to file"""
        file_path = filedialog.asksaveasfilename(
            title="Export JSON Configuration",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            parent=self
        )
        
        if file_path:
            try:
                json_content = self.json_editor.get(1.0, tk.END).strip()
                
                # Validate JSON
                config_dict = json.loads(json_content)
                
                # Write to file
                with open(file_path, 'w') as f:
                    json.dump(config_dict, f, indent=2)
                
                self.json_status_label.configure(text=f"✓ Exported: {Path(file_path).name}")
                self.log_message(f"Exported configuration to {file_path}", "SUCCESS")
            except json.JSONDecodeError as e:
                self.json_status_label.configure(text=f"✗ Invalid JSON: {e}")
                messagebox.showerror("Export Error", f"Invalid JSON: {e}")
            except Exception as e:
                self.json_status_label.configure(text=f"✗ Export failed: {e}")
                messagebox.showerror("Export Error", f"Failed to export: {e}")
    
    def validate_json(self):
        """Validate JSON in editor"""
        try:
            json_content = self.json_editor.get(1.0, tk.END).strip()
            config_dict = json.loads(json_content)
            
            # Try to create ProjectConfig from it
            ProjectConfig.from_dict(config_dict)
            
            self.json_status_label.configure(text="✓ Valid JSON configuration")
            messagebox.showinfo("Validation", "JSON configuration is valid!")
        except json.JSONDecodeError as e:
            self.json_status_label.configure(text=f"✗ Invalid JSON: {e}")
            messagebox.showerror("Validation Error", f"Invalid JSON syntax:\n{e}")
        except Exception as e:
            self.json_status_label.configure(text=f"✗ Invalid configuration: {e}")
            messagebox.showerror("Validation Error", f"Invalid configuration:\n{e}")
    
    def format_json(self):
        """Format JSON in editor"""
        try:
            json_content = self.json_editor.get(1.0, tk.END).strip()
            config_dict = json.loads(json_content)
            
            # Format with proper indentation
            formatted = json.dumps(config_dict, indent=2, sort_keys=False)
            
            # Update editor
            self.json_editor.delete(1.0, tk.END)
            self.json_editor.insert(1.0, formatted)
            
            self.json_status_label.configure(text="✓ JSON formatted")
        except json.JSONDecodeError as e:
            self.json_status_label.configure(text=f"✗ Cannot format invalid JSON: {e}")
            messagebox.showerror("Format Error", f"Cannot format invalid JSON:\n{e}")
    
    def _load_template_to_editor(self, template_name: str, template: dict) -> None:
        """Load a template into the JSON editor tab"""
        # Load template into editor
        self.json_editor.delete(1.0, tk.END)
        self.json_editor.insert(1.0, json.dumps(template, indent=2))
        
        # Update tree view
        self.update_json_tree(template)
        
        self.json_status_label.configure(text=f"✓ Loaded template: {template_name}")
        self.log_message(f"Loaded template into editor: {template_name}", "INFO")
    
    def on_json_change(self, event=None):
        """Handle changes in JSON editor"""
        try:
            json_content = self.json_editor.get(1.0, tk.END).strip()
            if json_content:
                config_dict = json.loads(json_content)
                self.update_json_tree(config_dict)
                self.json_status_label.configure(text="✓ Valid JSON")
        except json.JSONDecodeError:
            self.json_status_label.configure(text="⚠ Invalid JSON syntax")
        except Exception:
            pass
    
    def update_json_tree(self, data, parent='', key='Configuration'):
        """Update the JSON tree view"""
        if parent == '':
            # Clear existing tree
            for item in self.json_tree.get_children():
                self.json_tree.delete(item)
        
        if isinstance(data, dict):
            if parent == '':
                parent = self.json_tree.insert('', 'end', text=key, values=('', 'object'))
            
            for k, v in data.items():
                if isinstance(v, (dict, list)):
                    item = self.json_tree.insert(parent, 'end', text=k, values=('', type(v).__name__))
                    self.update_json_tree(v, item, k)
                else:
                    value_str = str(v) if v is not None else 'null'
                    type_str = type(v).__name__ if v is not None else 'null'
                    self.json_tree.insert(parent, 'end', text=k, values=(value_str, type_str))
        
        elif isinstance(data, list):
            if parent == '':
                parent = self.json_tree.insert('', 'end', text=key, values=('', 'array'))
            
            for i, v in enumerate(data):
                if isinstance(v, (dict, list)):
                    item = self.json_tree.insert(parent, 'end', text=f'[{i}]', values=('', type(v).__name__))
                    self.update_json_tree(v, item, f'[{i}]')
                else:
                    value_str = str(v) if v is not None else 'null'
                    type_str = type(v).__name__ if v is not None else 'null'
                    self.json_tree.insert(parent, 'end', text=f'[{i}]', values=(value_str, type_str))
    
    def load_current_config_to_json(self):
        """Load current configuration into JSON editor"""
        try:
            config_dict = asdict(self.current_config)
            json_content = json.dumps(config_dict, indent=2, default=str)
            
            self.json_editor.delete(1.0, tk.END)
            self.json_editor.insert(1.0, json_content)
            
            self.update_json_tree(config_dict)
            self.json_status_label.configure(text="✓ Current configuration loaded")
        except Exception as e:
            self.json_status_label.configure(text=f"✗ Failed to load config: {e}")
    
    # ============= Recent Projects Methods =============
    def load_recent_projects(self):
        """Load recent projects from storage"""
        try:
            recent_configs = self.project_manager.get_recent_configs()
            if recent_configs:
                project_names = [config.stem for config in recent_configs]
                self.recent_menu.configure(values=project_names)
                self.recent_var.set(project_names[0])
            else:
                self.recent_menu.configure(values=["No recent projects"])
                self.recent_var.set("No recent projects")
        except Exception as e:
            self.log_message(f"Failed to load recent projects: {e}", "WARNING")
    
    def load_recent_project(self, project_name: str):
        """Load a recent project"""
        if project_name == "No recent projects":
            return
        
        try:
            recent_configs = self.project_manager.get_recent_configs()
            project_path = next((config for config in recent_configs if config.stem == project_name), None)
            
            if project_path and project_path.exists():
                config = self.project_manager.load_config(project_path)
                if config:
                    self.current_config = config
                    self._update_ui_from_config()
                    self.log_message(f"Loaded project: {project_name}", "SUCCESS")
                else:
                    self.log_message(f"Failed to load project: {project_name}", "ERROR")
            else:
                self.log_message(f"Project not found: {project_name}", "ERROR")
                self.load_recent_projects()  # Refresh list
        except Exception as e:
            self.log_message(f"Error loading project: {e}", "ERROR")
    
    def add_to_recent_projects(self, project_path: str):
        """Add project to recent projects list"""
        try:
            recent_file = CONFIG_DIR / "recent_projects.json"
            recent = []
            
            if recent_file.exists():
                with open(recent_file, 'r') as f:
                    recent = json.load(f)
            
            # Remove if already exists
            recent = [p for p in recent if p != project_path]
            
            # Add to beginning
            recent.insert(0, project_path)
            
            # Keep only last 10
            recent = recent[:10]
            
            # Save back
            with open(recent_file, 'w') as f:
                json.dump(recent, f, indent=2)
            
            # Update UI
            self.load_recent_projects()
        except Exception as e:
            self.log_message(f"Failed to add to recent projects: {e}", "WARNING")
    
    # ============= Build Profile Methods =============
    def switch_build_profile(self, profile_name: str):
        """Switch to a different build profile"""
        if self.current_config.switch_profile(profile_name):
            self._update_ui_from_config()
            self.log_message(f"Switched to profile: {profile_name}", "INFO")
        else:
            self.log_message(f"Failed to switch to profile: {profile_name}", "ERROR")
    
    def add_build_profile(self):
        """Add a new build profile"""
        dialog = ctk.CTkInputDialog(
            text="Enter profile name:",
            title="Add Build Profile"
        )
        profile_name = dialog.get_input()
        
        if profile_name and profile_name not in self.current_config.build_profiles:
            # Create new profile based on current settings
            self._update_config_from_ui()
            new_config = BuildConfig()
            new_config.script_path = self.current_config.build.script_path
            new_config.exe_name = f"{self.current_config.build.exe_name}_{profile_name.lower()}"
            new_config.output_dir = self.current_config.build.output_dir
            
            if self.current_config.add_profile(profile_name, new_config):
                self._update_profile_menu()
                self.log_message(f"Added profile: {profile_name}", "SUCCESS")
            else:
                self.log_message(f"Failed to add profile: {profile_name}", "ERROR")
        elif profile_name in self.current_config.build_profiles:
            self.log_message(f"Profile '{profile_name}' already exists", "WARNING")
    
    def remove_build_profile(self):
        """Remove the current build profile"""
        current_profile = self.profile_var.get()
        if current_profile == "default":
            messagebox.showwarning("Cannot Remove", "Cannot remove the default profile")
            return
        
        if messagebox.askyesno("Remove Profile", f"Remove profile '{current_profile}'?"):
            if self.current_config.remove_profile(current_profile):
                self._update_profile_menu()
                self.log_message(f"Removed profile: {current_profile}", "SUCCESS")
            else:
                self.log_message(f"Failed to remove profile: {current_profile}", "ERROR")
    
    def _update_profile_menu(self):
        """Update the profile dropdown menu"""
        profiles = list(self.current_config.build_profiles.keys())
        self.profile_menu.configure(values=profiles)
        if self.current_config.active_profile in profiles:
            self.profile_var.set(self.current_config.active_profile)
    
    # ============= Template Methods =============
    def load_template(self, template_name: str):
        """Load a project template"""
        if template_name == "Select Template":
            return
        
        try:
            config = ProjectTemplates.create_from_template(template_name)
            self.current_config = config
            self._update_ui_from_config()
            self._update_profile_menu()
            self.log_message(f"Loaded template: {template_name}", "SUCCESS")
        except Exception as e:
            self.log_message(f"Failed to load template: {e}", "ERROR")
    
    def save_as_template(self):
        """Save current configuration as a template"""
        dialog = ctk.CTkInputDialog(
            text="Enter template name:",
            title="Save as Template"
        )
        template_name = dialog.get_input()
        
        if template_name:
            try:
                self._update_config_from_ui()
                self.project_manager.save_template(template_name, self.current_config)
                self.log_message(f"Saved as template: {template_name}", "SUCCESS")
            except Exception as e:
                self.log_message(f"Failed to save template: {e}", "ERROR")
    
    def _update_ui_impl(self):
        """Update UI elements from current configuration (implementation)."""
        # Update profile menu
        self._update_profile_menu()
        
        # Update build configuration fields
        build_config = self.current_config.build
        if hasattr(self, 'wizard_script_entry'):
            self.wizard_script_entry.delete(0, tk.END)
            self.wizard_script_entry.insert(0, build_config.script_path)
        
        if hasattr(self, 'exe_name_entry'):
            self.exe_name_entry.delete(0, tk.END)
            self.exe_name_entry.insert(0, build_config.exe_name)
        
        if hasattr(self, 'output_dir_entry'):
            self.output_dir_entry.delete(0, tk.END)
            self.output_dir_entry.insert(0, build_config.output_dir)
    
    def _update_config_impl(self):
        """Update configuration from UI inputs (implementation)."""
        # Update based on available UI elements
        if hasattr(self, 'wizard_mode') and self.wizard_mode:
            # Wizard mode updates
            if hasattr(self, 'wizard_script_entry'):
                script_path = self.validator.sanitize_input(self.wizard_script_entry.get())
                if self.validator.validate_file_path(script_path):
                    self.current_config.build.script_path = script_path
                    self.current_config.build.exe_name = Path(script_path).stem
                
                if hasattr(self, 'wizard_windowed_var'):
                    self.current_config.build.windowed = bool(self.wizard_windowed_var.get())
                
                if hasattr(self, 'wizard_onefile_var'):
                    self.current_config.build.one_file = bool(self.wizard_onefile_var.get())
        else:
            # Advanced mode updates
            if hasattr(self, 'script_entry'):
                script_path = self.validator.sanitize_input(self.script_entry.get())
                if self.validator.validate_file_path(script_path):
                    self.current_config.build.script_path = script_path
            
            if hasattr(self, 'exe_name_entry'):
                exe_name = self.validator.sanitize_input(self.exe_name_entry.get())
                if self.validator.validate_executable_name(exe_name):
                    self.current_config.build.exe_name = exe_name
            else:
                self.log_message("Invalid executable name", "WARNING")
        
        if hasattr(self, 'output_dir_entry'):
            output_dir = self.validator.sanitize_input(self.output_dir_entry.get())
            self.current_config.build.output_dir = output_dir
    
    def validate_build_inputs(self) -> bool:
        """Validate all build inputs for security and correctness"""
        # Validate script path
        if not self.current_config.build.script_path:
            messagebox.showerror("Validation Error", "Please select a Python script")
            return False
        
        if not self.validator.validate_file_path(self.current_config.build.script_path):
            messagebox.showerror("Validation Error", "Invalid script path. Please select a valid .py file")
            return False
        
        if not Path(self.current_config.build.script_path).exists():
            messagebox.showerror("Validation Error", "Selected script does not exist")
            return False
        
        # Validate executable name
        if not self.current_config.build.exe_name:
            messagebox.showerror("Validation Error", "Please enter an executable name")
            return False
        
        if not self.validator.validate_executable_name(self.current_config.build.exe_name):
            messagebox.showerror("Validation Error", "Invalid executable name. Use only letters, numbers, and underscores")
            return False
        
        # Validate output directory
        if not self.current_config.build.output_dir:
            messagebox.showerror("Validation Error", "Please specify an output directory")
            return False
        
        # Validate hidden imports
        for import_name in self.current_config.build.hidden_imports:
            if not self.validator.sanitize_input(import_name):
                messagebox.showerror("Validation Error", f"Invalid import name: {import_name}")
                return False
        
        # Validate data paths
        for source, target in self.current_config.build.data_paths:
            if not self.validator.sanitize_input(source) or not self.validator.sanitize_input(target):
                messagebox.showerror("Validation Error", "Invalid data path")
                return False
        
        return True
    
    # ============= Additional Helper Methods =============
    # Note: save_project is moved to Project Management section
    
    def _start_log_polling_placeholder(self):
        """Placeholder renamed to avoid duplicate with active implementation."""
        pass
    
    # Note: Moved to Dependency Management section as _check_setup_worker

# Utility classes for UI components
class ModernButton(ctk.CTkButton):
    """Modern styled button component"""
    
    def __init__(self, parent, **kwargs):
        modern_kwargs = {
            'corner_radius': 8,
            'height': 36,
            'font': ctk.CTkFont(size=12),
            **kwargs
        }
        super().__init__(parent, **modern_kwargs)

class ModernFrame(ctk.CTkFrame):
    """Modern styled frame component"""
    
    def __init__(self, parent, **kwargs):
        modern_kwargs = {
            'corner_radius': 12,
            'border_width': 0,
            **kwargs
        }
        super().__init__(parent, **modern_kwargs)

def install_missing_dependencies():
    """Install missing required dependencies"""
    missing = []
    for package in REQUIRED_PACKAGES:
        try:
            __import__(package.replace("-", "_"))
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"Installing missing dependencies: {', '.join(missing)}")
        for package in missing:
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                print(f"✓ Installed {package}")
            except Exception as e:
                print(f"✗ Failed to install {package}: {e}")
                return False
    
    # Note: win32crypt import is already handled at module level
    
    # Check for optional packages
    for package in OPTIONAL_PACKAGES:
        try:
            __import__(package.replace("-", "_"))
            print(f"✓ Optional package available: {package}")
        except ImportError:
            print(f"⚠ Optional package not installed: {package}")
    
    return True

def run_headless(args):
    """Run in headless/CLI mode"""
    import argparse
    
    parser = argparse.ArgumentParser(
        prog='py2win',
        description='Py2Win Premium - Convert Python scripts to Windows executables',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  py2win --config myproject.json --build
  py2win --script app.py --name MyApp --onefile --windowed --build
  py2win --config myproject.json --installer
  py2win --script app.py --analyze-deps
        """
    )
    
    # Configuration options
    parser.add_argument('-c', '--config', help='Load configuration from JSON file')
    parser.add_argument('-s', '--script', help='Python script to convert')
    parser.add_argument('-n', '--name', help='Output executable name')
    parser.add_argument('-o', '--output', default='./dist', help='Output directory')
    parser.add_argument('-i', '--icon', help='Icon file path')
    
    # Build options
    parser.add_argument('--onefile', action='store_true', help='Create single executable file')
    parser.add_argument('--windowed', action='store_true', help='Hide console window (for GUI apps)')
    parser.add_argument('--clean', action='store_true', default=True, help='Clean build directory')
    parser.add_argument('--backend', choices=['pyinstaller', 'nuitka'], default='pyinstaller', 
                       help='Build backend to use')
    parser.add_argument('--upx', action='store_true', help='Use UPX compression')
    parser.add_argument('--hidden-import', action='append', dest='hidden_imports',
                       help='Add hidden import (can be used multiple times)')
    parser.add_argument('--exclude', action='append', dest='excludes',
                       help='Exclude module (can be used multiple times)')
    parser.add_argument('--add-data', action='append', dest='data_files',
                       help='Add data file/folder in format SOURCE;DEST')
    
    # Actions
    parser.add_argument('--build', action='store_true', help='Build the executable')
    parser.add_argument('--installer', action='store_true', help='Create NSIS installer')
    parser.add_argument('--analyze-deps', action='store_true', help='Analyze dependencies')
    parser.add_argument('--detect-imports', action='store_true', help='Detect hidden imports')
    parser.add_argument('--save-config', help='Save configuration to JSON file')
    
    # Installer options
    parser.add_argument('--app-name', help='Application name for installer')
    parser.add_argument('--version', default='1.0.0', help='Application version')
    parser.add_argument('--company', help='Company name')
    parser.add_argument('--description', help='Application description')
    
    # Parse arguments
    parsed_args = parser.parse_args(args[1:])
    
    # Initialize components
    logger = RotatingLogger()
    
    # Load or create configuration
    if parsed_args.config:
        # Load from JSON file
        try:
            with open(parsed_args.config, 'r') as f:
                config_dict = json.load(f)
            config = ProjectConfig.from_dict(config_dict)
            logger.info(f"Loaded configuration from {parsed_args.config}")
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            return 1
    else:
        # Create from command line arguments
        config = ProjectConfig()
        
        if parsed_args.script:
            config.build.script_path = parsed_args.script
            config.project.name = Path(parsed_args.script).stem
        
        if parsed_args.name:
            config.build.exe_name = parsed_args.name
        
        config.build.output_dir = parsed_args.output
        config.build.one_file = parsed_args.onefile
        config.build.windowed = parsed_args.windowed
        config.build.clean_build = parsed_args.clean
        config.build.backend = parsed_args.backend
        config.build.use_upx = parsed_args.upx
        
        if parsed_args.icon:
            config.build.icon_path = parsed_args.icon
        
        if parsed_args.hidden_imports:
            config.build.hidden_imports = parsed_args.hidden_imports
        
        if parsed_args.excludes:
            config.build.exclude_modules = parsed_args.excludes
        
        if parsed_args.data_files:
            config.build.data_paths = []
            for data in parsed_args.data_files:
                if ';' in data:
                    source, dest = data.split(';', 1)
                    config.build.data_paths.append((source, dest))
                else:
                    config.build.data_paths.append((data, '.'))
        
        if parsed_args.version:
            config.build.version = parsed_args.version
    
    # Save configuration if requested
    if parsed_args.save_config:
        try:
            with open(parsed_args.save_config, 'w') as f:
                json.dump(asdict(config), f, indent=2, default=str)
            logger.info(f"Configuration saved to {parsed_args.save_config}")
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            return 1
    
    # Perform requested actions
    exit_code = 0
    
    # Analyze dependencies
    if parsed_args.analyze_deps:
        if not config.build.script_path:
            logger.error("No script specified for dependency analysis")
            return 1
        
        print("\n=== Dependency Analysis ===")
        analyzer = DependencyAnalyzer(sys.executable)
        
        deps = analyzer.get_dependencies(config.build.script_path)
        print(f"\nFound {len(deps)} dependencies:")
        for dep in sorted(deps):
            print(f"  • {dep}")
        
        diagnosis = analyzer.full_diagnosis(config.build.script_path)
        
        if diagnosis['missing_packages']:
            print(f"\n⚠ Missing packages ({len(diagnosis['missing_packages'])}):")
            for pkg in diagnosis['missing_packages']:
                print(f"  ✗ {pkg}")
        
        if diagnosis['version_conflicts']:
            print(f"\n⚠ Version conflicts:")
            for conflict in diagnosis['version_conflicts']:
                print(f"  • {conflict}")
        
        print(f"\n✓ Compatible packages: {len(diagnosis['compatible_packages'])}")
    
    # Detect hidden imports
    if parsed_args.detect_imports:
        if not config.build.script_path:
            logger.error("No script specified for import detection")
            return 1
        
        print("\n=== Hidden Import Detection ===")
        detector = HiddenImportDetector()
        imports = detector.detect_imports(config.build.script_path)
        
        if imports['static']:
            print(f"\nStatic imports ({len(imports['static'])}):")
            for imp in sorted(imports['static']):
                print(f"  • {imp}")
        
        if imports['dynamic']:
            print(f"\nDynamic imports ({len(imports['dynamic'])}):")
            for imp in sorted(imports['dynamic']):
                print(f"  • {imp}")
        
        if imports['suggestions']:
            print(f"\nSuggested imports ({len(imports['suggestions'])}):")
            for imp in sorted(imports['suggestions']):
                print(f"  ? {imp}")
    
    # Build executable
    if parsed_args.build:
        if not config.build.script_path:
            logger.error("No script specified for building")
            return 1
        
        print(f"\n=== Building {config.build.exe_name or 'executable'} ===")
        print(f"Script: {config.build.script_path}")
        print(f"Backend: {config.build.backend}")
        print(f"Output: {config.build.output_dir}")
        
        orchestrator = BuildOrchestrator()
        success = orchestrator.build(config.build)
        output_path = None
        if success:
            # Derive expected output path
            output_path = Path(config.build.output_dir) / (config.build.exe_name or "")
            print(f"\n✓ Build successful!")
            print(f"Executable: {output_path}")
        else:
            print(f"\n✗ Build failed!")
            exit_code = 1
    
    # Create installer
    if parsed_args.installer:
        if not config.build.exe_name:
            logger.error("No executable name specified for installer")
            return 1
        
        print(f"\n=== Creating NSIS Installer ===")
        
        installer_config = InstallerConfig(
            app_name=parsed_args.app_name or config.project.name or config.build.exe_name,
            version=parsed_args.version or config.build.version,
            company=parsed_args.company or config.project.author,
            description=parsed_args.description or config.project.description
        )
        
        installer = NSISInstaller()
        exe_path = Path(config.build.output_dir) / f"{config.build.exe_name}.exe"
        
        if not exe_path.exists():
            print(f"✗ Executable not found: {exe_path}")
            print("  Please build the executable first with --build")
            return 1
        
        try:
            installer_path = installer.build_installer(
                exe_path=str(exe_path),
                config=installer_config,
                signing_config=config.signing
            )
            print(f"\n✓ Installer created: {installer_path}")
        except Exception as e:
            print(f"\n✗ Installer creation failed: {e}")
            exit_code = 1
    
    return exit_code

def main():
    """Main entry point"""
    # Ensure dependencies are installed
    if not install_missing_dependencies():
        print("Failed to install required dependencies")
        return 1
    
    # Handle command line arguments
    if len(sys.argv) > 1:
        # Check for headless mode or CLI arguments
        if "--headless" in sys.argv or not sys.stdin.isatty() or any(arg.startswith('-') for arg in sys.argv[1:]):
            return run_headless(sys.argv)
    
    # Run GUI mode
    try:
        app = Py2WinMainApp()
        app.mainloop()
        return 0
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
        return 1
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())