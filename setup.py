#!/usr/bin/env python3
"""
Setup script for Py2Win Premium v5.0.0
Installs dependencies and configures the application
"""

import sys
import os
import subprocess
import platform
from pathlib import Path

def check_python_version():
    """Check if Python version meets requirements"""
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required")
        print(f"   Current version: {sys.version}")
        return False
    print(f"✓ Python {sys.version.split()[0]} detected")
    return True

def check_platform():
    """Check if running on Windows"""
    if platform.system() != "Windows":
        print("⚠ Warning: Py2Win is designed for Windows")
        print(f"   Current platform: {platform.system()}")
        response = input("Continue anyway? (y/n): ")
        if response.lower() != 'y':
            return False
    else:
        print(f"✓ Windows {platform.release()} detected")
    return True

def install_dependencies():
    """Install required Python packages"""
    print("\n📦 Installing dependencies...")
    
    # Core dependencies
    packages = [
        "pyinstaller>=6.0.0",
        "customtkinter>=5.2.0",
        "pillow>=10.0.0",
        "requests>=2.31.0",
        "setuptools>=68.0.0",
        "wheel>=0.41.0"
    ]
    
    # Windows-specific
    if platform.system() == "Windows":
        packages.append("pywin32>=306")
    
    for package in packages:
        print(f"  Installing {package}...")
        try:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", 
                "--upgrade", package
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"    ✓ {package.split('>=')[0]} installed")
        except subprocess.CalledProcessError:
            print(f"    ❌ Failed to install {package}")
            return False
    
    return True

def install_optional_packages():
    """Install optional packages"""
    print("\n📦 Optional packages:")
    
    optional = {
        "nuitka": "Alternative compiler for better performance",
        "pytest": "Testing framework",
        "black": "Code formatter",
        "pylint": "Code linter"
    }
    
    for package, description in optional.items():
        response = input(f"  Install {package} ({description})? (y/n): ")
        if response.lower() == 'y':
            try:
                subprocess.check_call([
                    sys.executable, "-m", "pip", "install", package
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f"    ✓ {package} installed")
            except subprocess.CalledProcessError:
                print(f"    ❌ Failed to install {package}")

def create_directories():
    """Create necessary directories"""
    print("\n📁 Creating directories...")
    
    dirs = [
        Path.home() / ".py2win",
        Path.home() / ".py2win" / "tools",
        Path.home() / ".py2win" / "cache",
        Path.home() / ".py2win" / "configs"
    ]
    
    for dir_path in dirs:
        dir_path.mkdir(parents=True, exist_ok=True)
        print(f"  ✓ {dir_path}")
    
    return True

def create_shortcuts():
    """Create desktop and start menu shortcuts (Windows only)"""
    if platform.system() != "Windows":
        return True
    
    print("\n🔗 Creating shortcuts...")
    
    try:
        import win32com.client  # type: ignore
        shell = win32com.client.Dispatch("WScript.Shell")
        
        # Desktop shortcut
        desktop = Path.home() / "Desktop"
        shortcut_path = desktop / "Py2Win Premium.lnk"
        
        shortcut = shell.CreateShortCut(str(shortcut_path))
        shortcut.Targetpath = sys.executable
        shortcut.Arguments = f'"{Path.cwd() / "py2win_premium_v5.py"}"'
        shortcut.WorkingDirectory = str(Path.cwd())
        shortcut.IconLocation = sys.executable
        shortcut.Description = "Py2Win Premium - Python to Windows Converter"
        shortcut.save()
        
        print(f"  ✓ Desktop shortcut created")
        return True
        
    except ImportError:
        print("  ⚠ Could not create shortcuts (pywin32 not available)")
        return True
    except Exception as e:
        print(f"  ⚠ Could not create shortcuts: {e}")
        return True

def test_installation():
    """Test if the application can be imported"""
    print("\n🧪 Testing installation...")
    
    try:
        # Test imports
        import customtkinter  # type: ignore
        import PIL  # type: ignore
        import pyinstaller  # type: ignore
        print("  ✓ All core modules imported successfully")
        
        # Test application
        print("  Testing application startup...")
        result = subprocess.run([
            sys.executable, "py2win_premium_v5.py", "--help"
        ], capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0:
            print("  ✓ Application starts successfully")
        else:
            print("  ⚠ Application test returned non-zero code")
        
        return True
        
    except ImportError as e:
        print(f"  ❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"  ❌ Test failed: {e}")
        return False

def main():
    """Main setup function"""
    print("=" * 50)
    print("     Py2Win Premium v5.0.0 Setup")
    print("=" * 50)
    print()
    
    # Check requirements
    if not check_python_version():
        return 1
    
    if not check_platform():
        return 1
    
    # Install dependencies
    if not install_dependencies():
        print("\n❌ Setup failed: Could not install dependencies")
        return 1
    
    # Optional packages
    install_optional_packages()
    
    # Create directories
    if not create_directories():
        print("\n❌ Setup failed: Could not create directories")
        return 1
    
    # Create shortcuts
    create_shortcuts()
    
    # Test installation
    if not test_installation():
        print("\n⚠ Setup completed with warnings")
    else:
        print("\n✅ Setup completed successfully!")
    
    print("\n" + "=" * 50)
    print("To start Py2Win Premium:")
    print("  GUI Mode: python py2win_premium_v5.py")
    print("  CLI Mode: python py2win_premium_v5.py --help")
    print("  Windows: Double-click run_py2win.bat")
    print("=" * 50)
    
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n❌ Setup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)
