# Py2Win Premium AI Development Guide

This guide contains essential patterns and workflows for AI agents working with Py2Win Premium, a GUI application for converting Python scripts into Windows executables and installers.

## Core Architecture & Components

- **Main Entry Point**: `py2win_premium_v5.py` - Primary application with modular components
- **Configuration System**: Type-safe dataclasses for configuration management
- **Key Services**:
  ```python
  # Core services with clear responsibilities
  class BuildOrchestrator:
      def build_executable(self, config: BuildConfig) -> bool
      def _validate_build_config(self, config: BuildConfig) -> bool

  class HiddenImportDetector:
      def detect_imports(self, script_path: str) -> Dict[str, List[str]]
      def _static_analysis(self, script_path: str) -> List[str]

  # Project configuration using dataclasses
  @dataclass
  class BuildConfig:
      script_path: str
      exe_name: str
      output_dir: str = "./dist"
      one_file: bool = True
      windowed: bool = True
      backend: str = "pyinstaller"  # or "nuitka"
      version: str = "1.0.0"
      # See BuildConfig class for complete reference
  ```

## Development Workflows

### Environment Setup & Testing
```powershell
# Setup development environment
pip install -r requirements.txt

# Run test suite
python run_tests.py  # Uses unittest framework in tests/

# Key paths
~/.py2win/          # Configuration directory
%APPDATA%/Py2Win/logs/  # Application logs
~/.py2win/cache/    # Build artifacts cache
```

### Project Conventions

1. **Code Structure**:
   - UI components organized by tab in `py2win_premium_v5.py`
   - Thread-safe operations via `ThreadPoolExecutor`
   - Progress reporting through callback system

2. **Error Handling**:
   ```python
   # Example error handling pattern
   try:
       with RotatingLogger("build") as logger:
           build_result = orchestrator.build_executable(config)
           if not build_result:
               logger.error("Build failed - see logs for details")
   except BuildError as e:
       handle_build_failure(e)  # User feedback + cleanup
   ```

3. **Configuration Management**:
   ```json
   {
     "project": {
       "name": "MyApp",
       "version": "1.0.0"
     },
     "build_profiles": {
       "default": {
         "script_path": "main.py",
         "exe_name": "MyApp",
         "backend": "pyinstaller"
       }
     }
   }
   ```

## Integration Points

1. **Build System**:
   - PyInstaller (default) - Full Windows executable support
   - Nuitka (optional) - Enhanced performance builds
   - NSIS (`~/.py2win/tools/nsis/`) - Professional installers
   - UPX - Optional executable compression
   - Windows SDK - Code signing support

2. **Development Tasks**:
   - New build options: Extend `BuildConfig` + `_validate_build_config()`
   - Package support: Update `REQUIRED_PACKAGES`/`OPTIONAL_PACKAGES`
   - Templates: Modify `ProjectTemplates.get_templates()`

3. **Testing**:
   ```python
   # Integration test pattern (see test_integration.py)
   def test_build_flow(self):
       with tempfile.TemporaryDirectory() as tmp_dir:
           config = BuildConfig(
               script_path=self.test_script,
               output_dir=tmp_dir
           )
           self.assertTrue(
               BuildOrchestrator().build_executable(config)
           )