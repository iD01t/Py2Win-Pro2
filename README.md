# Py2Win Premium v5.0.0

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Version](https://img.shields.io/badge/Version-5.0.0-red)

**Py2Win Premium** is a comprehensive, enterprise-grade GUI application for converting Python scripts into Windows executables and installers. It features an intuitive modern interface, advanced dependency detection, multiple build backends, and professional installer creation.

## ✨ Features

### 🎯 Core Capabilities
- **Modern GUI Interface** - Built with CustomTkinter for a professional, dark-themed experience
- **Multiple Build Backends** - Support for both PyInstaller and Nuitka
- **NSIS Installer Creation** - Generate professional Windows installers
- **Advanced Import Detection** - Automatic discovery of hidden and dynamic imports
- **Dependency Analysis** - Complete dependency scanning and conflict detection
- **Code Signing Support** - Built-in support for signing executables and installers
- **Headless/CLI Mode** - Full command-line interface for automation

### 📋 Tab Features

#### Build Tab
- Script selection with drag-and-drop support
- One-file or directory output options
- Console/windowed mode selection
- Icon customization
- UPX compression support
- Clean build options

#### Imports Tab
- Automatic hidden import detection
- Static and dynamic import analysis
- Framework-specific import patterns
- Manual import management
- Import/export functionality

#### Assets Tab
- Data file management
- Directory inclusion
- Custom target path specification
- Drag-and-drop support
- Visual asset organization

#### Dependencies Tab
- Real-time dependency scanning
- Version conflict detection
- Missing package identification
- Compatibility checking
- Installation assistance

#### Advanced Tab
- Runtime hooks configuration
- Custom PyInstaller options
- Nuitka-specific settings
- Build optimization controls
- Debug options

#### Installer Tab
- NSIS installer configuration
- Desktop/Start Menu shortcuts
- EULA integration
- Banner image support
- Per-user/system installation
- Silent mode support

#### Settings Tab
- Theme customization (Dark/Light/System)
- UI scaling options
- Log retention settings
- Default directories
- Code signing configuration
- Cache management

#### JSON Tools Tab
- Configuration import/export
- JSON validation
- Template system
- Visual configuration editor
- Syntax highlighting

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/py2win-premium.git
cd py2win-premium

# Install dependencies
pip install -r requirements.txt

# Run the application
python py2win_premium_v5.py
```

### Basic Usage

#### GUI Mode
1. Launch the application
2. Select your Python script using the "Browse" button
3. Configure build options (one-file, windowed, etc.)
4. Click "Build Executable"
5. Optionally create an installer in the Installer tab

#### Command Line Mode

```bash
# Basic build
python py2win_premium_v5.py --script app.py --name MyApp --onefile --build

# With hidden imports
python py2win_premium_v5.py --script app.py --hidden-import numpy --hidden-import pandas --build

# Create installer
python py2win_premium_v5.py --config myproject.json --installer

# Analyze dependencies
python py2win_premium_v5.py --script app.py --analyze-deps

# Detect imports
python py2win_premium_v5.py --script app.py --detect-imports
```

## 📖 Documentation

### Project Configuration

Py2Win uses JSON configuration files to store project settings:

```json
{
  "project": {
    "name": "My Application",
    "version": "1.0.0",
    "author": "Your Name",
    "description": "Application description"
  },
  "build": {
    "script_path": "main.py",
    "exe_name": "MyApp",
    "output_dir": "./dist",
    "one_file": true,
    "windowed": true,
    "icon_path": "icon.ico",
    "hidden_imports": ["module1", "module2"],
    "backend": "pyinstaller"
  }
}
```

### Build Backends

#### PyInstaller (Default)
- Mature and stable
- Excellent compatibility
- Large file sizes
- Good for most applications

#### Nuitka (Optional)
- Compiles to C++
- Better performance
- Smaller file sizes
- Requires C++ compiler

### Advanced Features

#### Hidden Import Detection
The application uses multiple methods to detect imports:
1. **Static Analysis** - AST parsing of source code
2. **Dynamic Analysis** - Runtime import tracking
3. **Framework Detection** - Automatic detection of common frameworks
4. **Pattern Matching** - Intelligent import suggestions

#### Code Signing
Configure code signing in Settings tab:
1. Enable code signing
2. Select certificate (.pfx/.p12)
3. Enter certificate password
4. Choose timestamp server

#### Custom Hooks
Add runtime hooks for special initialization:
1. Navigate to Advanced tab
2. Add hook files
3. Configure hook execution order

## 🛠️ Development

### Project Structure

```
py2win-premium/
├── py2win_premium_v5.py    # Main application
├── requirements.txt         # Dependencies
├── README.md               # Documentation
├── LICENSE                 # License file
└── tests/                  # Unit tests
    └── test_*.py
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Testing

```bash
# Run unit tests
pytest tests/

# Run with coverage
pytest --cov=py2win_premium tests/
```

## 🔧 Troubleshooting

### Common Issues

#### Missing Dependencies
- Run `pip install -r requirements.txt`
- For optional packages, install as needed

#### Build Failures
- Check console output for errors
- Verify all imports are included
- Try different build backend
- Disable UPX compression

#### Installer Creation Fails
- Ensure NSIS is installed (auto-downloads on first use)
- Check executable exists in output directory
- Verify installer configuration

#### Import Errors
- Use Import Detection feature
- Add missing imports manually
- Check framework-specific requirements

### Debug Mode

Enable debug output:
```bash
python py2win_premium_v5.py --script app.py --build --debug
```

## 📋 System Requirements

- **Operating System**: Windows 10/11
- **Python**: 3.8 or higher
- **RAM**: 4GB minimum, 8GB recommended
- **Disk Space**: 500MB for application, varies for builds
- **Optional**: Visual Studio Build Tools (for Nuitka)

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [PyInstaller](https://www.pyinstaller.org/) - Primary build backend
- [Nuitka](https://nuitka.net/) - Alternative compiler
- [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) - Modern UI framework
- [NSIS](https://nsis.sourceforge.io/) - Installer system

## 📞 Support

- **Documentation**: See this README and in-app help
- **Issues**: Report bugs via GitHub Issues
- **Discussions**: Use GitHub Discussions for questions
- **Email**: support@py2win.example.com

## 🚦 Roadmap

### Version 5.1 (Planned)
- [ ] Linux/macOS support
- [ ] Cloud build service
- [ ] Plugin system
- [ ] Custom themes
- [ ] Build caching

### Version 5.2 (Future)
- [ ] AI-powered optimization
- [ ] Multi-project workspace
- [ ] Team collaboration
- [ ] Build statistics
- [ ] Performance profiling

---

**Copyright © 2025 - Py2Win Premium Development Team**
