#!/usr/bin/env python3
"""
Unit tests for HiddenImportDetector class
"""

import unittest
import tempfile
from pathlib import Path
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from py2win_premium_v5 import HiddenImportDetector

class TestHiddenImportDetector(unittest.TestCase):
    """Test cases for HiddenImportDetector"""
    
    def setUp(self):
        """Set up test environment"""
        self.detector = HiddenImportDetector()
        self.temp_dir = Path(tempfile.mkdtemp())
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_static_analysis_simple_imports(self):
        """Test static analysis with simple imports"""
        test_script = self.temp_dir / "test_imports.py"
        with open(test_script, 'w') as f:
            f.write('''
import os
import sys
from pathlib import Path
import json
from typing import List, Dict

def main():
    print("Hello World")
    return 0

if __name__ == "__main__":
    main()
            ''')
        
        imports = self.detector._static_analysis(str(test_script))
        
        self.assertIn("os", imports)
        self.assertIn("sys", imports)
        self.assertIn("pathlib", imports)
        self.assertIn("json", imports)
        self.assertIn("typing", imports)
    
    def test_static_analysis_from_imports(self):
        """Test static analysis with from imports"""
        test_script = self.temp_dir / "test_from_imports.py"
        with open(test_script, 'w') as f:
            f.write('''
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import numpy as np
import pandas as pd

def main():
    now = datetime.now()
    data = defaultdict(list)
    return 0

if __name__ == "__main__":
    main()
            ''')
        
        imports = self.detector._static_analysis(str(test_script))
        
        self.assertIn("datetime", imports)
        self.assertIn("collections", imports)
        self.assertIn("numpy", imports)
        self.assertIn("pandas", imports)
    
    def test_static_analysis_conditional_imports(self):
        """Test static analysis with conditional imports"""
        test_script = self.temp_dir / "test_conditional.py"
        with open(test_script, 'w') as f:
            f.write('''
import sys

try:
    import requests
except ImportError:
    requests = None

if sys.platform == "win32":
    import win32api
else:
    import subprocess

def main():
    if requests:
        print("Requests available")
    return 0

if __name__ == "__main__":
    main()
            ''')
        
        imports = self.detector._static_analysis(str(test_script))
        
        self.assertIn("sys", imports)
        self.assertIn("requests", imports)
        self.assertIn("win32api", imports)
        self.assertIn("subprocess", imports)
    
    def test_dynamic_analysis_framework_detection(self):
        """Test dynamic analysis framework detection"""
        test_script = self.temp_dir / "test_flask.py"
        with open(test_script, 'w') as f:
            f.write('''
from flask import Flask, request, jsonify
import werkzeug
from jinja2 import Template

app = Flask(__name__)

@app.route('/')
def hello():
    return "Hello World!"

if __name__ == "__main__":
    app.run()
            ''')
        
        imports = self.detector._dynamic_analysis(str(test_script))
        
        # Should detect Flask-related imports
        self.assertIn("flask", imports)
        self.assertIn("werkzeug", imports)
        self.assertIn("jinja2", imports)
    
    def test_dynamic_analysis_numpy_detection(self):
        """Test dynamic analysis numpy detection"""
        test_script = self.temp_dir / "test_numpy.py"
        with open(test_script, 'w') as f:
            f.write('''
import numpy as np
import pandas as pd
from matplotlib import pyplot as plt

def main():
    data = np.array([1, 2, 3, 4, 5])
    df = pd.DataFrame({'values': data})
    plt.plot(data)
    return 0

if __name__ == "__main__":
    main()
            ''')
        
        imports = self.detector._dynamic_analysis(str(test_script))
        
        # Should detect data science imports
        self.assertIn("numpy", imports)
        self.assertIn("pandas", imports)
        self.assertIn("matplotlib", imports)
    
    def test_detect_imports_integration(self):
        """Test full detect_imports integration"""
        test_script = self.temp_dir / "test_integration.py"
        with open(test_script, 'w') as f:
            f.write('''
import os
import sys
from pathlib import Path
import requests
from flask import Flask

app = Flask(__name__)

def main():
    print("Integration test")
    return 0

if __name__ == "__main__":
    main()
            ''')
        
        result = self.detector.detect_imports(str(test_script))
        
        self.assertIn("static", result)
        self.assertIn("dynamic", result)
        self.assertIn("suggestions", result)
        
        # Check static imports
        self.assertIn("os", result["static"])
        self.assertIn("sys", result["static"])
        self.assertIn("pathlib", result["static"])
        self.assertIn("requests", result["static"])
        self.assertIn("flask", result["static"])
        
        # Check dynamic imports (should include framework-specific)
        self.assertIn("flask", result["dynamic"])
        self.assertIn("werkzeug", result["dynamic"])
    
    def test_is_stdlib(self):
        """Test standard library detection"""
        # Standard library modules
        self.assertTrue(self.detector._is_stdlib("os"))
        self.assertTrue(self.detector._is_stdlib("sys"))
        self.assertTrue(self.detector._is_stdlib("json"))
        self.assertTrue(self.detector._is_stdlib("pathlib"))
        
        # Third-party modules
        self.assertFalse(self.detector._is_stdlib("requests"))
        self.assertFalse(self.detector._is_stdlib("numpy"))
        self.assertFalse(self.detector._is_stdlib("flask"))
        
        # Built-in modules
        self.assertTrue(self.detector._is_stdlib("builtins"))
        self.assertTrue(self.detector._is_stdlib("math"))

if __name__ == '__main__':
    unittest.main()
