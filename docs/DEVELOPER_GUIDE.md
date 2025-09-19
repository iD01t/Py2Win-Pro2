# Py2Win Premium v5.0.0 - Developer Guide

## Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Core Components](#core-components)
3. [Configuration System](#configuration-system)
4. [Build System](#build-system)
5. [UI Framework](#ui-framework)
6. [Testing](#testing)
7. [Contributing](#contributing)
8. [API Reference](#api-reference)

## Architecture Overview

Py2Win Premium follows a modular architecture with clear separation of concerns:

```
py2win_premium_v5.py
├── Data Classes (Configuration)
├── Core Services
│   ├── BuildOrchestrator
│   ├── HiddenImportDetector
│   ├── DependencyAnalyzer
│   ├── NSISInstaller
│   └── ProjectManager
├── UI Components
│   ├── Py2WinMainApp
│   ├── ModernFrame
│   └── ModernButton
└── Utilities
    ├── RotatingLogger
    ├── SecureStorage
    └── InputValidator
```

## Core Components

### Data Classes

#### ProjectConfig
Main configuration container with build profiles support:
```python
@dataclass
class ProjectConfig:
    project: ProjectInfo
    build_profiles: Dict[str, BuildConfig]
    active_profile: str
    advanced: AdvancedConfig
    installer: InstallerConfig
    signing: Optional[SigningConfig]
    metadata: Dict[str, Any]
```

#### BuildConfig
Individual build configuration:
```python
@dataclass
class BuildConfig:
    script_path: str
    exe_name: str
    output_dir: str
    one_file: bool
    windowed: bool
    backend: str
    hidden_imports: List[str]
    data_paths: List[Tuple[str, str]]
    # ... additional fields
```

### Core Services

#### BuildOrchestrator
Manages the build process for different backends:
```python
class BuildOrchestrator:
    def build_executable(self, config: BuildConfig) -> bool
    def _build_pyinstaller_command(self, config: BuildConfig) -> List[str]
    def _build_nuitka_command(self, config: BuildConfig) -> List[str]
    def _validate_build_config(self, config: BuildConfig) -> bool
```

#### HiddenImportDetector
Detects missing imports using static and dynamic analysis:
```python
class HiddenImportDetector:
    def detect_imports(self, script_path: str) -> Dict[str, List[str]]
    def _static_analysis(self, script_path: str) -> List[str]
    def _dynamic_analysis(self, script_path: str) -> List[str]
```

#### ProjectTemplates
Manages project templates for common application types:
```python
class ProjectTemplates:
    @staticmethod
    def get_templates() -> Dict[str, Dict[str, Any]]
    @staticmethod
    def create_from_template(template_name: str, custom_values: Dict[str, Any] = None) -> ProjectConfig
```

## Configuration System

### Configuration Hierarchy
1. **Default Values**: Built-in defaults in dataclasses
2. **Template Values**: Project template configurations
3. **User Settings**: User-customized values
4. **Runtime Overrides**: Command-line or UI overrides

### Configuration Persistence
- **JSON Format**: Human-readable configuration files
- **Automatic Backup**: Creates backups before saving
- **Version Control**: Tracks configuration format versions
- **Validation**: Validates configuration before loading

### Example Configuration
```json
{
  "project": {
    "name": "My Application",
    "version": "1.0.0",
    "author": "Developer",
    "description": "A sample application",
    "license": "MIT"
  },
  "build_profiles": {
    "default": {
      "script_path": "main.py",
      "exe_name": "MyApp",
      "output_dir": "./dist",
      "one_file": true,
      "windowed": false,
      "backend": "pyinstaller",
      "hidden_imports": ["requests", "numpy"]
    },
    "debug": {
      "script_path": "main.py",
      "exe_name": "MyApp_Debug",
      "output_dir": "./dist_debug",
      "one_file": false,
      "windowed": false,
      "backend": "pyinstaller",
      "debug_mode": true
    }
  },
  "active_profile": "default",
  "advanced": {
    "optimization_level": 1,
    "debug_mode": false,
    "console_mode": true
  }
}
```

## Build System

### Build Backends

#### PyInstaller
- **Command Generation**: Automatic command line construction
- **Spec File Support**: Generates and manages .spec files
- **Hidden Imports**: Automatic detection and manual addition
- **Data Files**: Bundles additional files and directories

#### Nuitka
- **Compilation**: Compiles Python to C++ for better performance
- **Optimization**: Multiple optimization levels
- **Standalone**: Creates standalone executables
- **Plugin System**: Supports Nuitka plugins

### Build Process
1. **Validation**: Validate configuration and dependencies
2. **Preparation**: Create output directories, clean previous builds
3. **Dependency Analysis**: Analyze and install required packages
4. **Command Generation**: Generate backend-specific commands
5. **Execution**: Run build process with progress monitoring
6. **Post-processing**: Code signing, installer creation, cleanup

### Error Handling
- **Validation Errors**: Catch configuration issues early
- **Build Failures**: Capture and display build errors
- **Dependency Issues**: Handle missing or incompatible packages
- **Permission Errors**: Handle file system access issues

## UI Framework

### CustomTkinter Integration
Py2Win uses CustomTkinter for modern UI components:
- **ModernFrame**: Custom frame with consistent styling
- **ModernButton**: Styled buttons with hover effects
- **Theme Support**: Dark/light theme switching
- **Responsive Layout**: Adapts to different window sizes

### UI Components

#### Main Application
```python
class Py2WinMainApp(ctk.CTk):
    def __init__(self):
        # Initialize UI components
        self.setup_ui()
        self.create_sidebar()
        self.create_main_area()
        self.create_console()
```

#### Tab System
- **Dynamic Tabs**: Tabs created on demand
- **State Management**: Preserves tab state
- **Validation**: Real-time input validation
- **Auto-save**: Automatic configuration saving

### Event Handling
- **Button Events**: Command callbacks for user actions
- **Input Validation**: Real-time validation with user feedback
- **Progress Updates**: Background task progress reporting
- **Error Display**: User-friendly error messages

## Testing

### Test Structure
```
tests/
├── __init__.py
├── test_build_orchestrator.py
├── test_import_detector.py
├── test_project_templates.py
└── test_integration.py
```

### Test Categories

#### Unit Tests
- **Component Testing**: Test individual classes and methods
- **Configuration Testing**: Test configuration loading/saving
- **Validation Testing**: Test input validation logic
- **Template Testing**: Test template creation and customization

#### Integration Tests
- **End-to-End**: Test complete workflows
- **Build Process**: Test actual build execution
- **File Operations**: Test file system operations
- **Error Handling**: Test error scenarios

### Running Tests
```bash
# Run all tests
python run_tests.py

# Run specific test file
python -m unittest tests.test_build_orchestrator

# Run with verbose output
python run_tests.py -v
```

### Test Data
- **Temporary Files**: Use tempfile for test data
- **Mock Objects**: Mock external dependencies
- **Cleanup**: Automatic cleanup after tests
- **Isolation**: Each test runs independently

## Contributing

### Development Setup
1. **Clone Repository**: Get the source code
2. **Install Dependencies**: `pip install -r requirements.txt`
3. **Run Tests**: Ensure all tests pass
4. **Create Branch**: Create feature branch
5. **Make Changes**: Implement your changes
6. **Test Changes**: Run tests and manual testing
7. **Submit PR**: Create pull request

### Code Style
- **PEP 8**: Follow Python style guidelines
- **Type Hints**: Use type annotations
- **Docstrings**: Document all public methods
- **Comments**: Explain complex logic

### Pull Request Process
1. **Fork Repository**: Create your fork
2. **Create Branch**: `git checkout -b feature/your-feature`
3. **Make Changes**: Implement your changes
4. **Add Tests**: Include tests for new functionality
5. **Update Documentation**: Update relevant docs
6. **Submit PR**: Create pull request with description

### Issue Reporting
- **Bug Reports**: Include steps to reproduce
- **Feature Requests**: Describe use case and benefits
- **Performance Issues**: Include system information
- **Documentation**: Report unclear or missing docs

## API Reference

### Core Classes

#### ProjectConfig
```python
class ProjectConfig:
    def add_profile(self, name: str, config: BuildConfig = None) -> bool
    def remove_profile(self, name: str) -> bool
    def switch_profile(self, name: str) -> bool
    @property
    def build(self) -> BuildConfig
```

#### BuildOrchestrator
```python
class BuildOrchestrator:
    def build_executable(self, config: BuildConfig) -> bool
    def _validate_build_config(self, config: BuildConfig) -> bool
    def _build_pyinstaller_command(self, config: BuildConfig) -> List[str]
    def _build_nuitka_command(self, config: BuildConfig) -> List[str]
```

#### HiddenImportDetector
```python
class HiddenImportDetector:
    def detect_imports(self, script_path: str) -> Dict[str, List[str]]
    def _static_analysis(self, script_path: str) -> List[str]
    def _dynamic_analysis(self, script_path: str) -> List[str]
    def _is_stdlib(self, module_name: str) -> bool
```

#### ProjectTemplates
```python
class ProjectTemplates:
    @staticmethod
    def get_templates() -> Dict[str, Dict[str, Any]]
    @staticmethod
    def create_from_template(template_name: str, custom_values: Dict[str, Any] = None) -> ProjectConfig
    @staticmethod
    def _merge_values(base: Dict[str, Any], custom: Dict[str, Any]) -> Dict[str, Any]
```

### Utility Classes

#### InputValidator
```python
class InputValidator:
    @staticmethod
    def validate_file_path(path: str) -> bool
    @staticmethod
    def validate_executable_name(name: str) -> bool
    @staticmethod
    def sanitize_input(text: str) -> str
    @staticmethod
    def validate_url(url: str) -> bool
```

#### SecureStorage
```python
class SecureStorage:
    def store_password(self, key: str, password: str) -> bool
    def retrieve_password(self, key: str) -> Optional[str]
    def delete_password(self, key: str) -> bool
    def list_keys(self) -> List[str]
```

### Configuration Classes

#### ProjectInfo
```python
@dataclass
class ProjectInfo:
    name: str
    version: str
    author: str
    description: str
    license: str
```

#### BuildConfig
```python
@dataclass
class BuildConfig:
    script_path: str
    exe_name: str
    output_dir: str
    one_file: bool
    windowed: bool
    backend: str
    hidden_imports: List[str]
    data_paths: List[Tuple[str, str]]
    # ... additional fields
```

#### AdvancedConfig
```python
@dataclass
class AdvancedConfig:
    optimization_level: int
    debug_mode: bool
    console_mode: bool
    upx_compression: bool
    # ... additional fields
```

---

**Py2Win Premium v5.0.0** - Developer documentation for contributors and advanced users.
