#!/usr/bin/env python3
"""
Demo Application for Py2Win Premium Testing
This script demonstrates various Python features to test the build process.
"""

import sys
import os
import json
import time
import threading
from datetime import datetime
from pathlib import Path

# Optional imports for testing detection
try:
    import tkinter as tk
    from tkinter import messagebox
    HAS_GUI = True
except ImportError:
    HAS_GUI = False

__version__ = "1.0.0"
__author__ = "Py2Win Demo"

class DemoApplication:
    """Simple demo application with various features"""
    
    def __init__(self):
        self.data_dir = Path("data")
        self.config_file = "config.json"
        self.running = False
        
    def print_banner(self):
        """Print application banner"""
        banner = f"""
╔══════════════════════════════════════╗
║     Py2Win Demo Application v{__version__}    ║
║         Successfully Built!          ║
╚══════════════════════════════════════╝
        """
        print(banner)
        
    def check_environment(self):
        """Check and display environment information"""
        print("\n🔍 Environment Information:")
        print(f"  • Python Version: {sys.version}")
        print(f"  • Platform: {sys.platform}")
        print(f"  • Executable: {sys.executable}")
        print(f"  • Current Directory: {os.getcwd()}")
        print(f"  • GUI Available: {HAS_GUI}")
        
    def test_file_operations(self):
        """Test file I/O operations"""
        print("\n📁 Testing File Operations:")
        
        # Create test directory
        test_dir = Path("test_output")
        test_dir.mkdir(exist_ok=True)
        print(f"  ✓ Created directory: {test_dir}")
        
        # Write test file
        test_file = test_dir / "test.txt"
        test_file.write_text(f"Test file created at {datetime.now()}")
        print(f"  ✓ Created file: {test_file}")
        
        # Read test file
        content = test_file.read_text()
        print(f"  ✓ Read file content: {content[:50]}...")
        
        # Create JSON config
        config = {
            "app": "Py2Win Demo",
            "version": __version__,
            "timestamp": datetime.now().isoformat()
        }
        
        config_file = test_dir / "config.json"
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"  ✓ Created JSON config: {config_file}")
        
    def test_threading(self):
        """Test threading capabilities"""
        print("\n🔄 Testing Threading:")
        
        def worker(name, duration):
            print(f"  • Thread {name} started")
            time.sleep(duration)
            print(f"  • Thread {name} completed")
        
        threads = []
        for i in range(3):
            t = threading.Thread(target=worker, args=(f"Worker-{i+1}", 0.5))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        print("  ✓ All threads completed")
        
    def test_gui(self):
        """Test GUI capabilities if available"""
        if not HAS_GUI:
            print("\n🖼️ GUI Testing: Skipped (tkinter not available)")
            return
            
        print("\n🖼️ Testing GUI:")
        
        root = tk.Tk()
        root.withdraw()  # Hide main window
        
        result = messagebox.askyesno(
            "Py2Win Demo",
            "This executable was built with Py2Win!\n\nDo you want to see more information?"
        )
        
        if result:
            info = f"""
Application: {__author__}
Version: {__version__}
Python: {sys.version.split()[0]}
Executable: {os.path.basename(sys.executable)}
            """
            messagebox.showinfo("Application Info", info)
        
        root.destroy()
        print("  ✓ GUI test completed")
        
    def interactive_mode(self):
        """Run in interactive mode"""
        print("\n🎮 Interactive Mode:")
        print("  Commands: 'test', 'info', 'gui', 'quit'")
        
        while True:
            try:
                command = input("\n> Enter command: ").strip().lower()
                
                if command == "quit":
                    print("Goodbye!")
                    break
                elif command == "test":
                    self.test_file_operations()
                    self.test_threading()
                elif command == "info":
                    self.check_environment()
                elif command == "gui":
                    self.test_gui()
                else:
                    print(f"Unknown command: {command}")
                    
            except KeyboardInterrupt:
                print("\nInterrupted!")
                break
            except Exception as e:
                print(f"Error: {e}")
                
    def run(self):
        """Main application entry point"""
        self.print_banner()
        self.check_environment()
        
        # Run tests
        print("\n🧪 Running Tests...")
        self.test_file_operations()
        self.test_threading()
        
        # Check for GUI
        if HAS_GUI and not any(arg in sys.argv for arg in ["--no-gui", "--console"]):
            self.test_gui()
        
        # Interactive mode if not in silent mode
        if "--interactive" in sys.argv:
            self.interactive_mode()
        elif "--silent" not in sys.argv:
            print("\n✅ All tests completed successfully!")
            print("\nPress Enter to exit...")
            input()

def main():
    """Main entry point"""
    app = DemoApplication()
    
    try:
        app.run()
        return 0
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
