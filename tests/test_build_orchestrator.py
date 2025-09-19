#!/usr/bin/env python3
"""
Unit tests for BuildOrchestrator class
"""

import unittest
import tempfile
import shutil
from pathlib import Path
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from py2win_premium_v5 import BuildOrchestrator, BuildConfig, ProjectConfig

class TestBuildOrchestrator(unittest.TestCase):
    """Test cases for BuildOrchestrator"""
    
    def setUp(self):
        """Set up test environment"""
        self.orchestrator = BuildOrchestrator()
        self.temp_dir = Path(tempfile.mkdtemp())
        self.test_script = self.temp_dir / "test_app.py"
        
        # Create a simple test script
        with open(self.test_script, 'w') as f:
            f.write('''
#!/usr/bin/env python3
"""Test application for Py2Win testing"""

def main():
    print("Hello from Py2Win test app!")
    return 0

if __name__ == "__main__":
    exit(main())
            ''')
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_validate_build_config_valid(self):
        """Test validation with valid configuration"""
        config = BuildConfig(
            script_path=str(self.test_script),
            exe_name="test_app",
            output_dir=str(self.temp_dir / "dist")
        )
        
        result = self.orchestrator._validate_build_config(config)
        self.assertTrue(result)
    
    def test_validate_build_config_invalid_script(self):
        """Test validation with non-existent script"""
        config = BuildConfig(
            script_path="nonexistent.py",
            exe_name="test_app",
            output_dir=str(self.temp_dir / "dist")
        )
        
        result = self.orchestrator._validate_build_config(config)
        self.assertFalse(result)
    
    def test_validate_build_config_missing_exe_name(self):
        """Test validation with missing executable name"""
        config = BuildConfig(
            script_path=str(self.test_script),
            exe_name="",
            output_dir=str(self.temp_dir / "dist")
        )
        
        result = self.orchestrator._validate_build_config(config)
        self.assertFalse(result)
    
    def test_build_pyinstaller_command(self):
        """Test PyInstaller command generation"""
        config = BuildConfig(
            script_path=str(self.test_script),
            exe_name="test_app",
            output_dir=str(self.temp_dir / "dist"),
            one_file=True,
            windowed=False,
            hidden_imports=["requests", "numpy"]
        )
        
        cmd = self.orchestrator._build_pyinstaller_command(config)
        
        self.assertIn("pyinstaller", cmd[0])
        self.assertIn("--onefile", cmd)
        self.assertIn("--name", cmd)
        self.assertIn("test_app", cmd)
        self.assertIn("--hidden-import", cmd)
        self.assertIn("requests", cmd)
        self.assertIn("numpy", cmd)
    
    def test_build_nuitka_command(self):
        """Test Nuitka command generation"""
        config = BuildConfig(
            script_path=str(self.test_script),
            exe_name="test_app",
            output_dir=str(self.temp_dir / "dist"),
            backend="nuitka",
            one_file=True
        )
        
        cmd = self.orchestrator._build_nuitka_command(config)
        
        self.assertIn("nuitka", cmd[0])
        self.assertIn("--onefile", cmd)
        self.assertIn("--output-filename=test_app.exe", cmd)
    
    def test_extract_version_from_script(self):
        """Test version extraction from script"""
        # Create script with version info
        version_script = self.temp_dir / "versioned_app.py"
        with open(version_script, 'w') as f:
            f.write('''
#!/usr/bin/env python3
"""Test application with version"""

__version__ = "2.1.0"

def main():
    print(f"Version: {__version__}")
    return 0

if __name__ == "__main__":
    exit(main())
            ''')
        
        version = self.orchestrator._extract_version(str(version_script))
        self.assertEqual(version, "2.1.0")
    
    def test_extract_version_no_version(self):
        """Test version extraction when no version is found"""
        version = self.orchestrator._extract_version(str(self.test_script))
        self.assertIsNone(version)

class TestProjectConfig(unittest.TestCase):
    """Test cases for ProjectConfig with build profiles"""
    
    def setUp(self):
        """Set up test environment"""
        self.config = ProjectConfig()
    
    def test_default_profile_creation(self):
        """Test that default profile is created automatically"""
        self.assertIn("default", self.config.build_profiles)
        self.assertEqual(self.config.active_profile, "default")
    
    def test_add_profile(self):
        """Test adding a new profile"""
        success = self.config.add_profile("debug")
        self.assertTrue(success)
        self.assertIn("debug", self.config.build_profiles)
    
    def test_add_duplicate_profile(self):
        """Test adding duplicate profile fails"""
        self.config.add_profile("debug")
        success = self.config.add_profile("debug")
        self.assertFalse(success)
    
    def test_remove_profile(self):
        """Test removing a profile"""
        self.config.add_profile("debug")
        success = self.config.remove_profile("debug")
        self.assertTrue(success)
        self.assertNotIn("debug", self.config.build_profiles)
    
    def test_remove_default_profile_fails(self):
        """Test that removing default profile fails"""
        success = self.config.remove_profile("default")
        self.assertFalse(success)
        self.assertIn("default", self.config.build_profiles)
    
    def test_switch_profile(self):
        """Test switching between profiles"""
        self.config.add_profile("debug")
        success = self.config.switch_profile("debug")
        self.assertTrue(success)
        self.assertEqual(self.config.active_profile, "debug")
    
    def test_switch_nonexistent_profile(self):
        """Test switching to non-existent profile fails"""
        success = self.config.switch_profile("nonexistent")
        self.assertFalse(success)
        self.assertEqual(self.config.active_profile, "default")
    
    def test_build_property(self):
        """Test build property returns active profile"""
        debug_config = BuildConfig(exe_name="debug_app")
        self.config.add_profile("debug", debug_config)
        self.config.switch_profile("debug")
        
        self.assertEqual(self.config.build.exe_name, "debug_app")

if __name__ == '__main__':
    unittest.main()
