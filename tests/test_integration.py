#!/usr/bin/env python3
"""
Integration tests for Py2Win Premium
"""

import unittest
import tempfile
import shutil
from pathlib import Path
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from py2win_premium_v5 import (
    ProjectConfig, BuildConfig, ProjectTemplates, 
    HiddenImportDetector, BuildOrchestrator
)

class TestIntegration(unittest.TestCase):
    """Integration tests for Py2Win Premium"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.test_script = self.temp_dir / "integration_test.py"
        
        # Create a comprehensive test script
        with open(self.test_script, 'w') as f:
            f.write('''
#!/usr/bin/env python3
"""
Integration test application for Py2Win Premium
Tests various Python features and imports
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

# Third-party imports (if available)
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

def process_data(data: List[Dict]) -> Optional[Dict]:
    """Process input data and return results"""
    if not data:
        return None
    
    results = {
        "count": len(data),
        "timestamp": datetime.now().isoformat(),
        "processed": True
    }
    
    if HAS_NUMPY:
        # Simulate numpy processing
        values = [item.get("value", 0) for item in data]
        results["mean"] = sum(values) / len(values) if values else 0
    
    return results

def fetch_data(url: str) -> Optional[Dict]:
    """Fetch data from URL if requests is available"""
    if not HAS_REQUESTS:
        return {"error": "requests not available"}
    
    try:
        # Simulate API call
        response = {"status": "success", "data": []}
        return response
    except Exception as e:
        return {"error": str(e)}

def main():
    """Main application entry point"""
    print("Py2Win Integration Test Application")
    print(f"Python version: {sys.version}")
    print(f"Platform: {sys.platform}")
    
    # Test data processing
    test_data = [
        {"id": 1, "value": 10, "name": "Item 1"},
        {"id": 2, "value": 20, "name": "Item 2"},
        {"id": 3, "value": 30, "name": "Item 3"}
    ]
    
    results = process_data(test_data)
    if results:
        print(f"Processed {results['count']} items")
        if "mean" in results:
            print(f"Mean value: {results['mean']}")
    
    # Test data fetching
    api_result = fetch_data("https://api.example.com/data")
    print(f"API result: {api_result}")
    
    # Test file operations
    output_file = Path("output.json")
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"Results saved to {output_file}")
    
    return 0

if __name__ == "__main__":
    exit(main())
            ''')
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_template_to_build_workflow(self):
        """Test complete workflow from template to build configuration"""
        # Create project from template
        config = ProjectTemplates.create_from_template("CLI Application")
        
        # Customize the configuration
        config.project.name = "Integration Test App"
        config.project.author = "Test Author"
        config.build.script_path = str(self.test_script)
        config.build.exe_name = "integration_test"
        config.build.output_dir = str(self.temp_dir / "dist")
        
        # Verify configuration
        self.assertEqual(config.project.name, "Integration Test App")
        self.assertEqual(config.build.script_path, str(self.test_script))
        self.assertEqual(config.build.exe_name, "integration_test")
        
        # Test build profile management
        config.add_profile("debug", BuildConfig(
            script_path=str(self.test_script),
            exe_name="integration_test_debug",
            output_dir=str(self.temp_dir / "dist_debug"),
            debug_mode=True
        ))
        
        self.assertIn("debug", config.build_profiles)
        self.assertEqual(len(config.build_profiles), 2)  # default + debug
    
    def test_import_detection_integration(self):
        """Test import detection with real Python script"""
        detector = HiddenImportDetector()
        result = detector.detect_imports(str(self.test_script))
        
        # Verify static imports are detected
        self.assertIn("static", result)
        self.assertIn("dynamic", result)
        self.assertIn("suggestions", result)
        
        # Check for expected static imports
        static_imports = result["static"]
        self.assertIn("os", static_imports)
        self.assertIn("sys", static_imports)
        self.assertIn("json", static_imports)
        self.assertIn("pathlib", static_imports)
        self.assertIn("datetime", static_imports)
        self.assertIn("typing", static_imports)
        
        # Check for conditional imports
        self.assertIn("requests", static_imports)
        self.assertIn("numpy", static_imports)
        
        # Check dynamic analysis
        dynamic_imports = result["dynamic"]
        # Should detect framework patterns even if not directly imported
        self.assertIsInstance(dynamic_imports, list)
    
    def test_build_configuration_validation(self):
        """Test build configuration validation"""
        orchestrator = BuildOrchestrator()
        
        # Valid configuration
        valid_config = BuildConfig(
            script_path=str(self.test_script),
            exe_name="test_app",
            output_dir=str(self.temp_dir / "dist")
        )
        
        self.assertTrue(orchestrator._validate_build_config(valid_config))
        
        # Invalid configurations
        invalid_configs = [
            BuildConfig(script_path="nonexistent.py", exe_name="test", output_dir=str(self.temp_dir)),
            BuildConfig(script_path=str(self.test_script), exe_name="", output_dir=str(self.temp_dir)),
            BuildConfig(script_path=str(self.test_script), exe_name="test", output_dir="")
        ]
        
        for config in invalid_configs:
            self.assertFalse(orchestrator._validate_build_config(config))
    
    def test_command_generation(self):
        """Test build command generation"""
        orchestrator = BuildOrchestrator()
        
        config = BuildConfig(
            script_path=str(self.test_script),
            exe_name="test_app",
            output_dir=str(self.temp_dir / "dist"),
            one_file=True,
            windowed=False,
            hidden_imports=["requests", "numpy"],
            backend="pyinstaller"
        )
        
        # Test PyInstaller command
        cmd = orchestrator._build_pyinstaller_command(config)
        self.assertIn("pyinstaller", cmd[0])
        self.assertIn("--onefile", cmd)
        self.assertIn("--name", cmd)
        self.assertIn("test_app", cmd)
        self.assertIn("--hidden-import", cmd)
        self.assertIn("requests", cmd)
        self.assertIn("numpy", cmd)
        self.assertIn(str(self.test_script), cmd)
    
    def test_project_config_serialization(self):
        """Test project configuration serialization and deserialization"""
        # Create a complex configuration
        config = ProjectTemplates.create_from_template("Data Science")
        config.project.name = "Test Data Science App"
        config.project.author = "Test Author"
        config.build.script_path = str(self.test_script)
        config.build.exe_name = "test_data_app"
        config.build.output_dir = str(self.temp_dir / "dist")
        
        # Add custom profile
        config.add_profile("production", BuildConfig(
            script_path=str(self.test_script),
            exe_name="test_data_app_prod",
            output_dir=str(self.temp_dir / "dist_prod"),
            optimization_level=2
        ))
        
        # Test serialization
        from dataclasses import asdict
        config_dict = asdict(config)
        
        self.assertIn("project", config_dict)
        self.assertIn("build_profiles", config_dict)
        self.assertIn("active_profile", config_dict)
        self.assertEqual(config_dict["active_profile"], "default")
        self.assertEqual(len(config_dict["build_profiles"]), 2)
    
    def test_error_handling(self):
        """Test error handling in various scenarios"""
        detector = HiddenImportDetector()
        orchestrator = BuildOrchestrator()
        
        # Test with non-existent file
        result = detector.detect_imports("nonexistent.py")
        self.assertIn("static", result)
        self.assertIn("dynamic", result)
        # Should handle gracefully
        
        # Test with invalid build config
        invalid_config = BuildConfig(
            script_path="nonexistent.py",
            exe_name="test",
            output_dir=str(self.temp_dir)
        )
        
        self.assertFalse(orchestrator._validate_build_config(invalid_config))
    
    def test_template_customization(self):
        """Test template customization and merging"""
        # Test custom values merging
        custom_values = {
            "project": {
                "name": "Custom Data Science App",
                "author": "Custom Author",
                "version": "2.0.0"
            },
            "build": {
                "exe_name": "custom_data_app",
                "hidden_imports": ["custom_module", "special_lib"]
            }
        }
        
        config = ProjectTemplates.create_from_template("Data Science", custom_values)
        
        # Check custom values are applied
        self.assertEqual(config.project.name, "Custom Data Science App")
        self.assertEqual(config.project.author, "Custom Author")
        self.assertEqual(config.project.version, "2.0.0")
        self.assertEqual(config.build.exe_name, "custom_data_app")
        
        # Check original values are preserved
        self.assertIn("numpy", config.build.hidden_imports)
        self.assertIn("pandas", config.build.hidden_imports)
        self.assertIn("custom_module", config.build.hidden_imports)
        self.assertIn("special_lib", config.build.hidden_imports)

if __name__ == '__main__':
    unittest.main()
