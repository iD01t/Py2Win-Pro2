# Py2Win Premium v5.0.0 - User Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Getting Started](#getting-started)
4. [User Interface](#user-interface)
5. [Project Templates](#project-templates)
6. [Build Profiles](#build-profiles)
7. [Advanced Features](#advanced-features)
8. [Command Line Interface](#command-line-interface)
9. [Troubleshooting](#troubleshooting)
10. [FAQ](#faq)

## Introduction

Py2Win Premium v5.0.0 is a comprehensive tool for packaging Python applications into Windows executables and installers. It supports multiple build backends (PyInstaller, Nuitka), advanced dependency analysis, and enterprise features.

### Key Features
- **Multiple Build Backends**: PyInstaller and Nuitka support
- **Project Templates**: Pre-configured templates for common application types
- **Build Profiles**: Multiple build configurations per project
- **Advanced Dependency Analysis**: Static and dynamic import detection
- **NSIS Installer Creation**: Professional Windows installers
- **Code Signing**: Digital signing of executables and installers
- **Recent Projects**: Quick access to recently worked on projects
- **Theme Customization**: Dark/light themes with color schemes
- **Command Line Interface**: Headless operation support

## Installation

### Prerequisites
- Windows 10/11 (64-bit)
- Python 3.8 or higher
- 4GB RAM minimum (8GB recommended)
- 2GB free disk space

### Quick Installation
1. Download the latest release from GitHub
2. Run `setup.py` to install dependencies:
   ```bash
   python setup.py
   ```
3. Launch the application:
   ```bash
   python py2win_premium_v5.py
   ```

### Manual Installation
1. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Install optional dependencies for enhanced features:
   ```bash
   pip install nuitka  # For Nuitka backend
   pip install pywin32  # For Windows-specific features
   ```

## Getting Started

### First Launch
1. Start Py2Win Premium
2. The application will automatically check for missing dependencies
3. Choose between Wizard Mode (simplified) or Advanced Mode (full control)

### Creating Your First Project
1. **Select a Template**: Choose from CLI Application, GUI Application, Web Service, Data Science, Game, or Desktop App (PyQt)
2. **Configure Basic Settings**:
   - Select your Python script
   - Enter executable name
   - Choose output directory
3. **Build Your Application**: Click "Build Executable" to create your .exe file

## User Interface

### Main Window Layout
- **Sidebar**: Navigation menu with recent projects and mode toggle
- **Main Area**: Tabbed interface for different configuration sections
- **Console**: Real-time build logs and status messages

### Navigation Tabs
- **Home**: Welcome screen with quick actions
- **Build**: Main build configuration (Wizard/Advanced modes)
- **Imports**: Hidden import management and detection
- **Assets**: Data files and directories to include
- **Dependencies**: Dependency analysis and management
- **Advanced**: Advanced build options and optimization
- **Installer**: NSIS installer configuration
- **Settings**: Application preferences and themes
- **JSON Tools**: Raw configuration editing

## Project Templates

### Available Templates

#### CLI Application
- **Purpose**: Command-line applications
- **Features**: Console mode, one-file builds
- **Hidden Imports**: click, argparse
- **Best For**: Scripts, utilities, command-line tools

#### GUI Application
- **Purpose**: Graphical user interface applications
- **Features**: Windowed mode, one-file builds
- **Hidden Imports**: tkinter, customtkinter, PIL
- **Best For**: Desktop applications with GUI

#### Web Service
- **Purpose**: Web applications and APIs
- **Features**: Multi-file builds, console mode
- **Hidden Imports**: flask, werkzeug, jinja2, click
- **Best For**: Web servers, APIs, microservices

#### Data Science
- **Purpose**: Data analysis and machine learning applications
- **Features**: Multi-file builds, optimized for large libraries
- **Hidden Imports**: numpy, pandas, matplotlib, scipy, sklearn
- **Best For**: Data analysis tools, ML applications

#### Game
- **Purpose**: Game applications
- **Features**: Windowed mode, data file support
- **Hidden Imports**: pygame, numpy
- **Best For**: Games, interactive applications

#### Desktop App (PyQt)
- **Purpose**: Professional desktop applications
- **Features**: Windowed mode, one-file builds
- **Hidden Imports**: PyQt5, PyQt5.QtCore, PyQt5.QtGui, PyQt5.QtWidgets
- **Best For**: Professional desktop software

### Using Templates
1. Go to the Build tab
2. Select a template from the dropdown
3. Customize the generated configuration
4. Save your project

## Build Profiles

### Creating Build Profiles
Build profiles allow you to maintain multiple build configurations for the same project:

1. **Add Profile**: Click "+ Add Profile" in the Build tab
2. **Configure**: Set different options for each profile (Debug, Release, etc.)
3. **Switch**: Use the profile dropdown to switch between configurations

### Profile Types
- **Default**: Standard build configuration
- **Debug**: Debug builds with additional logging
- **Release**: Optimized production builds
- **Custom**: User-defined configurations

### Profile Management
- **Switch Profiles**: Use the dropdown menu
- **Remove Profiles**: Click "- Remove" (cannot remove default)
- **Duplicate Settings**: New profiles inherit current settings

## Advanced Features

### Hidden Import Detection
The application automatically detects missing imports using:
- **Static Analysis**: AST parsing of your Python code
- **Dynamic Analysis**: Runtime analysis and framework detection
- **Manual Addition**: Add custom imports as needed

### Dependency Analysis
- **Automatic Detection**: Scans for required packages
- **Version Checking**: Ensures compatibility
- **Missing Dependencies**: Highlights packages that need installation

### Code Signing
Configure digital signing for your executables:
1. Go to Settings tab
2. Enter certificate details
3. Enable signing in build configuration
4. Sign both executables and installers

### NSIS Installer Creation
Create professional Windows installers:
1. Configure installer settings in the Installer tab
2. Set application information (name, version, company)
3. Configure installation options
4. Build installer alongside executable

## Command Line Interface

### Basic Usage
```bash
python py2win_premium_v5.py --headless <command> [options]
```

### Available Commands

#### Build Command
```bash
python py2win_premium_v5.py --headless build --script app.py --exe-name MyApp --output ./dist
```

#### Installer Command
```bash
python py2win_premium_v5.py --headless installer --config project.json
```

#### Analyze Dependencies
```bash
python py2win_premium_v5.py --headless analyze-deps --script app.py
```

#### Detect Imports
```bash
python py2win_premium_v5.py --headless detect-imports --script app.py
```

### Configuration Files
Use JSON configuration files for complex projects:
```json
{
  "project": {
    "name": "My Application",
    "version": "1.0.0",
    "author": "Your Name"
  },
  "build": {
    "script_path": "app.py",
    "exe_name": "MyApp",
    "output_dir": "./dist",
    "one_file": true,
    "windowed": false
  }
}
```

## Troubleshooting

### Common Issues

#### Build Failures
- **Missing Dependencies**: Check the Dependencies tab for missing packages
- **Invalid Script Path**: Ensure the Python script exists and is accessible
- **Permission Errors**: Run as administrator if needed
- **Antivirus Interference**: Add Py2Win to antivirus exclusions

#### Import Errors
- **Hidden Imports**: Add missing modules in the Imports tab
- **Dynamic Imports**: Use the dynamic analysis feature
- **Framework Dependencies**: Select appropriate project template

#### Performance Issues
- **Large Applications**: Use multi-file builds instead of one-file
- **Memory Usage**: Close other applications during builds
- **Slow Builds**: Enable build caching in Advanced settings

### Debug Mode
Enable debug mode for detailed logging:
1. Go to Advanced tab
2. Check "Debug Mode"
3. Review console output for detailed information

### Log Files
Check log files in:
- `%APPDATA%/Py2Win Premium/logs/`
- Console output in the application

## FAQ

### Q: Which build backend should I use?
**A**: 
- **PyInstaller**: Best compatibility, good for most applications
- **Nuitka**: Better performance, smaller executables, but longer build times

### Q: Why is my executable so large?
**A**: 
- Use multi-file builds instead of one-file
- Enable UPX compression
- Remove unnecessary dependencies
- Use Nuitka backend for better optimization

### Q: How do I include data files?
**A**: 
- Use the Assets tab to add data files and directories
- Specify source and destination paths
- Files will be bundled with your executable

### Q: Can I create installers for my application?
**A**: 
- Yes, use the Installer tab to configure NSIS installers
- Set application information and installation options
- Build both executable and installer together

### Q: How do I sign my executable?
**A**: 
- Obtain a code signing certificate
- Configure signing settings in the Settings tab
- Enable signing in your build configuration

### Q: Can I use Py2Win with virtual environments?
**A**: 
- Yes, Py2Win will use the current Python environment
- Ensure all dependencies are installed in your virtual environment
- Use the Advanced tab to specify custom Python executable

### Q: How do I update Py2Win?
**A**: 
- Download the latest release from GitHub
- Run the setup script to update dependencies
- Your projects and settings will be preserved

## Support

For additional support:
- Check the GitHub Issues page
- Review the documentation
- Contact the development team

---

**Py2Win Premium v5.0.0** - Professional Python to Windows packaging made easy.
