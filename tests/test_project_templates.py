#!/usr/bin/env python3
"""
Unit tests for ProjectTemplates class
"""

import unittest
import sys
from os.path import dirname, abspath

# Add parent directory to path for imports
sys.path.insert(0, dirname(dirname(abspath(__file__))))

from py2win_premium_v5 import ProjectTemplates, ProjectConfig

class TestProjectTemplates(unittest.TestCase):
    """Test cases for ProjectTemplates"""
    
    def test_get_templates(self):
        """Test getting available templates"""
        templates = ProjectTemplates.get_templates()
        
        self.assertIsInstance(templates, dict)
        self.assertIn("CLI Application", templates)
        self.assertIn("GUI Application", templates)
        self.assertIn("Web Service", templates)
        self.assertIn("Data Science", templates)
        self.assertIn("Game", templates)
        self.assertIn("Desktop App (PyQt)", templates)
    
    def test_template_structure(self):
        """Test template structure is correct"""
        templates = ProjectTemplates.get_templates()
        
        for _template_name, template in templates.items():
            self.assertIn("project", template)
            self.assertIn("build", template)
            self.assertIn("advanced", template)
            
            # Check project structure
            project = template["project"]
            self.assertIn("name", project)
            self.assertIn("version", project)
            self.assertIn("author", project)
            self.assertIn("description", project)
            
            # Check build structure
            build = template["build"]
            self.assertIn("script_path", build)
            self.assertIn("exe_name", build)
            self.assertIn("output_dir", build)
            self.assertIn("one_file", build)
            self.assertIn("windowed", build)
            self.assertIn("backend", build)
    
    def test_create_from_template_cli(self):
        """Test creating CLI application from template"""
        config = ProjectTemplates.create_from_template("CLI Application")
        
        self.assertIsInstance(config, ProjectConfig)
        self.assertEqual(config.project.name, "My CLI App")
        self.assertEqual(config.project.description, "A command-line application")
        self.assertFalse(config.build.windowed)
        self.assertTrue(config.build.one_file)
        self.assertIn("click", config.build.hidden_imports)
        self.assertIn("argparse", config.build.hidden_imports)
    
    def test_create_from_template_gui(self):
        """Test creating GUI application from template"""
        config = ProjectTemplates.create_from_template("GUI Application")
        
        self.assertIsInstance(config, ProjectConfig)
        self.assertEqual(config.project.name, "My GUI App")
        self.assertEqual(config.project.description, "A graphical user interface application")
        self.assertTrue(config.build.windowed)
        self.assertTrue(config.build.one_file)
        self.assertIn("tkinter", config.build.hidden_imports)
        self.assertIn("customtkinter", config.build.hidden_imports)
        self.assertIn("PIL", config.build.hidden_imports)
    
    def test_create_from_template_web_service(self):
        """Test creating web service from template"""
        config = ProjectTemplates.create_from_template("Web Service")
        
        self.assertIsInstance(config, ProjectConfig)
        self.assertEqual(config.project.name, "My Web Service")
        self.assertEqual(config.project.description, "A web service application")
        self.assertFalse(config.build.windowed)
        self.assertFalse(config.build.one_file)
        self.assertIn("flask", config.build.hidden_imports)
        self.assertIn("werkzeug", config.build.hidden_imports)
        self.assertIn("jinja2", config.build.hidden_imports)
    
    def test_create_from_template_data_science(self):
        """Test creating data science app from template"""
        config = ProjectTemplates.create_from_template("Data Science")
        
        self.assertIsInstance(config, ProjectConfig)
        self.assertEqual(config.project.name, "My Data Science App")
        self.assertEqual(config.project.description, "A data science application")
        self.assertFalse(config.build.windowed)
        self.assertFalse(config.build.one_file)
        self.assertIn("numpy", config.build.hidden_imports)
        self.assertIn("pandas", config.build.hidden_imports)
        self.assertIn("matplotlib", config.build.hidden_imports)
        self.assertIn("scipy", config.build.hidden_imports)
        self.assertIn("sklearn", config.build.hidden_imports)
    
    def test_create_from_template_game(self):
        """Test creating game from template"""
        config = ProjectTemplates.create_from_template("Game")
        
        self.assertIsInstance(config, ProjectConfig)
        self.assertEqual(config.project.name, "My Game")
        self.assertEqual(config.project.description, "A game application")
        self.assertTrue(config.build.windowed)
        self.assertTrue(config.build.one_file)
        self.assertIn("pygame", config.build.hidden_imports)
        self.assertIn("numpy", config.build.hidden_imports)
    
    def test_create_from_template_pyqt(self):
        """Test creating PyQt app from template"""
        config = ProjectTemplates.create_from_template("Desktop App (PyQt)")
        
        self.assertIsInstance(config, ProjectConfig)
        self.assertEqual(config.project.name, "My Desktop App")
        self.assertEqual(config.project.description, "A PyQt desktop application")
        self.assertTrue(config.build.windowed)
        self.assertTrue(config.build.one_file)
        self.assertIn("PyQt5", config.build.hidden_imports)
        self.assertIn("PyQt5.QtCore", config.build.hidden_imports)
        self.assertIn("PyQt5.QtGui", config.build.hidden_imports)
        self.assertIn("PyQt5.QtWidgets", config.build.hidden_imports)
    
    def test_create_from_nonexistent_template(self):
        """Test creating from non-existent template raises error"""
        with self.assertRaises(ValueError):
            ProjectTemplates.create_from_template("Nonexistent Template")
    
    def test_create_with_custom_values(self):
        """Test creating template with custom values"""
        custom_values = {
            "project": {
                "name": "Custom App",
                "author": "Custom Author"
            },
            "build": {
                "exe_name": "custom_app",
                "hidden_imports": ["custom_module"]
            }
        }
        
        config = ProjectTemplates.create_from_template("CLI Application", custom_values)
        
        self.assertEqual(config.project.name, "Custom App")
        self.assertEqual(config.project.author, "Custom Author")
        self.assertEqual(config.build.exe_name, "custom_app")
        self.assertIn("custom_module", config.build.hidden_imports)
        # Should still have original values
        self.assertIn("click", config.build.hidden_imports)
        self.assertIn("argparse", config.build.hidden_imports)
    
    def test_merge_values(self):
        """Test _merge_values helper method"""
        base = {
            "project": {
                "name": "Base App",
                "version": "1.0.0",
                "author": "Base Author"
            },
            "build": {
                "exe_name": "base_app",
                "hidden_imports": ["base_module"]
            }
        }
        
        custom = {
            "project": {
                "name": "Custom App",
                "description": "Custom Description"
            },
            "build": {
                "hidden_imports": ["custom_module"]
            },
            "new_section": {
                "new_key": "new_value"
            }
        }
        
        result = ProjectTemplates._merge_values(base, custom)
        
        # Check merged values
        self.assertEqual(result["project"]["name"], "Custom App")
        self.assertEqual(result["project"]["version"], "1.0.0")  # From base
        self.assertEqual(result["project"]["author"], "Base Author")  # From base
        self.assertEqual(result["project"]["description"], "Custom Description")  # From custom
        
        self.assertEqual(result["build"]["exe_name"], "base_app")  # From base
        self.assertEqual(result["build"]["hidden_imports"], ["custom_module"])  # From custom
        
        self.assertIn("new_section", result)  # From custom
        self.assertEqual(result["new_section"]["new_key"], "new_value")

if __name__ == '__main__':
    unittest.main()
