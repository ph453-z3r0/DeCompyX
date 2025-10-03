# Reverse Engineering Automation Tool

**NTRO Approved - Government of India Project**

A comprehensive automated reverse engineering tool that integrates multiple open-source analysis frameworks for security research and malware analysis.

## 🎯 Overview

This tool automates various reverse engineering techniques using state-of-the-art open-source tools:

- **Static Analysis**: Ghidra, Radare2, Capstone
- **Dynamic Analysis**: x64dbg, QEMU, Frida
- **Symbolic Execution**: Angr, KLEE
- **Automated Deobfuscation**: Loki, Dfsan, ML-based techniques
- **String and Data Mining**: strings, Binwalk, custom algorithms

## 🚀 Features

### Static Analysis
- Binary disassembly and decompilation
- Import/Export analysis
- Function discovery and analysis
- String extraction and analysis
- Entropy calculation for packing detection
- PE/ELF format analysis

### Dynamic Analysis
- Process execution monitoring
- Network behavior analysis
- Filesystem change tracking
- Memory behavior analysis
- Anti-debugging detection
- Registry monitoring (Windows)

### Symbolic Execution
- Path exploration and analysis
- Vulnerability detection
- Constraint solving
- Test case generation
- Control flow analysis

### Automated Deobfuscation
- Obfuscation pattern detection
- String deobfuscation
- Control flow deobfuscation
- Anti-analysis technique detection
- Machine learning-based deobfuscation

### String and Data Mining
- Advanced string extraction
- URL and path extraction
- API call identification
- Cryptographic material detection
- Configuration data extraction
- Encoded string detection

## 📋 Requirements

### System Requirements
- Python 3.8 or higher
- 4GB RAM minimum (8GB recommended)
- 10GB free disk space
- Linux, Windows, or macOS

### Dependencies
See `requirements.txt` for complete list of Python packages.

## 🛠️ Installation

### 1. Clone the Repository
```bash
git clone <repository-url>
cd reverse-eng
```

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 3. Install External Tools
```bash
python scripts/install_tools.py
```

### 4. Configure the Tool
Edit `config.json` to customize analysis options and tool paths.

## 🎮 Usage

### Basic Usage
```bash
python RevEngX.py <target_binary>
```

### Advanced Usage
```bash
# Specify analysis types
python rea.py target.exe --analysis-types static dynamic

# Quick scan only
python rea.py target.exe --quick

# Custom output directory
python rea.py target.exe --output /path/to/results

# Custom configuration
python rea.py target.exe --config custom_config.json
```

### Command Line Options
- `--analysis-types`: Specify which analysis types to perform
- `--quick`: Perform quick scan only
- `--config`: Use custom configuration file
- `--output`: Specify output directory for results

## 📊 Analysis Types

### Static Analysis
```bash
python rea.py target.exe --analysis-types static
```

**Tools Used:**
- Ghidra: Binary analysis and decompilation
- Radare2: Disassembly and debugging
- Capstone: Disassembly framework

**Output:**
- Function analysis
- Import/Export tables
- String extraction
- Entropy analysis
- Binary format information

### Dynamic Analysis
```bash
python rea.py target.exe --analysis-types dynamic
```

**Tools Used:**
- x64dbg: Windows debugging
- QEMU: Emulation
- Frida: Dynamic instrumentation

**Output:**
- Process execution logs
- Network behavior
- Filesystem changes
- Memory analysis
- Anti-analysis detection

### Symbolic Execution
```bash
python rea.py target.exe --analysis-types symbolic
```

**Tools Used:**
- Angr: Symbolic execution framework
- KLEE: Symbolic virtual machine

**Output:**
- Path exploration results
- Vulnerability detection
- Constraint solving
- Test case generation

### Deobfuscation
```bash
python rea.py target.exe --analysis-types deobfuscation
```

**Tools Used:**
- Loki: Malware classification
- Dfsan: Data flow sanitizer
- Custom ML algorithms

**Output:**
- Obfuscation detection
- Deobfuscated strings
- Pattern analysis
- Anti-analysis techniques

### String Mining
```bash
python rea.py target.exe --analysis-types string_mining
```

**Tools Used:**
- strings: String extraction
- Binwalk: Binary analysis
- Custom algorithms

**Output:**
- Extracted strings
- URLs and paths
- API calls
- Cryptographic material
- Configuration data

## 📁 Project Structure

```
reverse-eng/
├── RevEngX.py                         # Main automation script
├── config.json                        # Configuration file
├── requirements.txt                   # Python dependencies
├── README.md                         # This file
├── modules/                          # Analysis modules
│   ├── static_analysis.py
│   ├── dynamic_analysis.py
│   ├── symbolic_execution.py
│   ├── deobfuscation.py
│   └── string_mining.py
├── utils/                            # Utility modules
│   ├── config_manager.py
│   └── report_generator.py
├── scripts/                          # Installation scripts
│   └── install_tools.py
├── tools/                            # External tools
├── results/                          # Analysis results
├── reports/                          # Generated reports
└── logs/                             # Log files
```

## ⚙️ Configuration

The tool uses `config.json` for configuration. Key sections:

### Tools Configuration
```json
{
  "tools": {
    "ghidra": {
      "enabled": true,
      "path": "ghidra",
      "timeout": 300
    },
    "radare2": {
      "enabled": true,
      "path": "r2",
      "timeout": 60
    }
  }
}
```

### Analysis Configuration
```json
{
  "static_analysis": {
    "enabled": true,
    "timeout": 300,
    "extract_strings": true,
    "analyze_imports": true
  }
}
```

### Output Configuration
```json
{
  "output": {
    "results_dir": "results",
    "reports_dir": "reports",
    "format": "json"
  }
}
```

## 📈 Reports

The tool generates comprehensive reports in multiple formats:

### HTML Report
- Interactive web-based report
- Collapsible sections
- Detailed analysis results
- Visual indicators

### JSON Report
- Machine-readable format
- Complete analysis data
- Structured output
- Easy integration

### Summary Report
- Text-based summary
- Key findings
- Quick overview
- Human-readable format

## 🔒 Security Considerations

### Sandbox Mode
- Isolated execution environment
- Network isolation
- Quarantined results
- Hash verification

### Data Protection
- Encrypted output options
- Secure temporary files
- Access controls
- Audit logging

## 🐛 Troubleshooting

### Common Issues

1. **Tool Not Found**
   - Check tool paths in `config.json`
   - Run `python scripts/install_tools.py`
   - Verify system PATH

2. **Permission Denied**
   - Run with appropriate permissions
   - Check file access rights
   - Verify sandbox directory

3. **Analysis Timeout**
   - Increase timeout values in config
   - Use smaller analysis scope
   - Check system resources

4. **Memory Issues**
   - Increase system RAM
   - Use 64-bit Python
   - Reduce analysis scope

### Debug Mode
```bash
python rea.py target.exe --debug
```

## 🤝 Contributing

This is a government-approved project. Contributions are welcome but must follow security guidelines.

### Development Setup
```bash
# Install development dependencies
pip install -r requirements.txt
pip install pytest black flake8

# Run tests
pytest

# Format code
black .

# Lint code
flake8 .
```

## 📄 License

This project is developed under NTRO (National Technical Research Organisation) approval for government security research purposes.

## 🏛️ Government Approval

This tool has been approved by the Government of India through NTRO for:
- Security research and analysis
- Malware analysis and reverse engineering
- Cybersecurity education and training
- Government security operations

## 📞 Support

For support and questions:
- Check the documentation
- Review configuration options
- Examine log files
- Contact the development team

## 🔄 Updates

Regular updates include:
- New analysis techniques
- Improved tool integration
- Enhanced reporting
- Security improvements
- Performance optimizations

## 📚 References

- [Ghidra Documentation](https://ghidra-sre.org/)
- [Radare2 Documentation](https://radare.gitbooks.io/radare2book/)
- [Angr Documentation](https://docs.angr.io/)
- [Frida Documentation](https://frida.re/docs/)
- [NTRO Guidelines](https://ntro.gov.in/)

---

**Disclaimer**: This tool is intended for authorized security research and analysis only. Users must comply with applicable laws and regulations.
