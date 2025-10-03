# Reverse Engineering Automation Tool - Usage Examples

**NTRO Approved - Government of India Project**

This document demonstrates practical usage examples of the Reverse Engineering Automation Tool.

## Table of Contents

1. [Basic Usage](#basic-usage)
2. [Command Line Examples](#command-line-examples)
3. [Analysis Types](#analysis-types)
4. [Configuration Examples](#configuration-examples)
5. [Output Examples](#output-examples)
6. [Python API Examples](#python-api-examples)

## Basic Usage

### 1. Help and Command Options

```bash
# Display help information
python RevEngX.py --help
```

**Output:**
```
usage: reverse_engineering_automation.py [-h]
                                         [--analysis-types {static,dynamic,symbolic,deobfuscation,string_mining} [{static,dynamic,symbolic,deobfuscation,string_mining} ...]]
                                         [--quick] [--config CONFIG]
                                         [--output OUTPUT]
                                         target

Reverse Engineering Automation Tool - NTRO Approved

positional arguments:
  target                Path to target binary/executable

options:
  -h, --help            show this help message and exit
  --analysis-types      Types of analysis to perform (default: all)
  --quick               Perform quick scan only
  --config CONFIG       Configuration file path
  --output OUTPUT       Output directory for results
```

### 2. Quick Scan

```bash
# Perform a quick scan for basic information
python rea.py test_sample.exe --quick
```

**Output:**
```
2025-10-03 10:37:05,034 - RE_Automation - INFO - Performing quick scan of: test_sample.exe
Analysis completed. Results saved to: results\analysis_results_20251003_103705.json
```

### 3. Single Analysis Type

```bash
# Static analysis only
python rea.py test_sample.exe --analysis-types static
```

**Output:**
```
2025-10-03 10:37:11,968 - RE_Automation - INFO - Starting analysis of target: test_sample.exe
2025-10-03 10:37:11,969 - RE_Automation - INFO - Performing static analysis...
2025-10-03 10:37:12,004 - RE_Automation - INFO - Analysis completed. Report saved to: reports\re_analysis_report_test_sample_20251003_103712.html
Analysis completed. Results saved to: results\analysis_results_20251003_103712.json
Comprehensive report: reports\re_analysis_report_test_sample_20251003_103712.html
```

### 4. Multiple Analysis Types

```bash
# Static, dynamic, and string mining analysis
python rea.py test_sample.exe --analysis-types static dynamic string_mining --output demo_results
```

**Output:**
```
2025-10-03 10:37:43,864 - RE_Automation - INFO - Starting analysis of target: test_sample.exe
2025-10-03 10:37:43,864 - RE_Automation - INFO - Performing static analysis...
2025-10-03 10:37:43,882 - RE_Automation - INFO - Performing dynamic analysis...
2025-10-03 10:37:44,050 - RE_Automation - INFO - Performing string and data mining...
2025-10-03 10:37:44,229 - RE_Automation - INFO - Analysis completed. Report saved to: reports\re_analysis_report_test_sample_20251003_103744.html
Analysis completed. Results saved to: demo_results\analysis_results_20251003_103744.json
Comprehensive report: reports\re_analysis_report_test_sample_20251003_103744.html
```

## Command Line Examples

### 1. Basic Analysis Commands

```bash
# Analyze with all available analysis types (default)
python rea.py malware_sample.exe

# Quick scan for initial assessment
python rea.py malware_sample.exe --quick

# Static analysis only
python rea.py malware_sample.exe --analysis-types static

# Dynamic analysis only
python rea.py malware_sample.exe --analysis-types dynamic

# String mining only
python rea.py malware_sample.exe --analysis-types string_mining
```

### 2. Advanced Analysis Commands

```bash
# Multiple analysis types
python rea.py malware_sample.exe --analysis-types static dynamic

# All analysis types except one
python rea.py malware_sample.exe --analysis-types static dynamic deobfuscation string_mining

# Custom output directory
python rea.py malware_sample.exe --output /path/to/results

# Custom configuration file
python rea.py malware_sample.exe --config custom_config.json
```

### 3. Batch Processing Examples

```bash
# Process multiple files (Windows)
for %f in (*.exe) do python rea.py "%f" --quick

# Process multiple files (Linux/Mac)
for file in *.exe; do python rea.py "$file" --quick; done

# Process with specific analysis types
for file in *.exe; do python rea.py "$file" --analysis-types static string_mining; done
```

## Analysis Types

### 1. Static Analysis

**Purpose:** Analyze binary structure without execution

**Tools Used:**
- Ghidra (NSA framework)
- Radare2 (Disassembly)
- Capstone (Disassembly framework)

**Example:**
```bash
python rea.py sample.exe --analysis-types static
```

**Output Structure:**
```json
{
  "static": {
    "target": "sample.exe",
    "analysis_type": "static",
    "tools_used": ["capstone"],
    "results": {
      "file_analysis": {
        "size": 412,
        "header_hex": "4d5a9090...",
        "magic_bytes": "4d5a9090",
        "is_executable": true,
        "file_type": "PE"
      },
      "entropy": {
        "entropy": 3.5333,
        "is_likely_packed": false,
        "file_size": 412
      },
      "strings": {
        "strings": [],
        "count": 0
      }
    }
  }
}
```

### 2. Dynamic Analysis

**Purpose:** Monitor program behavior during execution

**Tools Used:**
- x64dbg (Windows debugger)
- QEMU (Emulator)
- Frida (Dynamic instrumentation)

**Example:**
```bash
python rea.py sample.exe --analysis-types dynamic
```

### 3. Symbolic Execution

**Purpose:** Explore all possible program paths

**Tools Used:**
- Angr (Python framework)
- KLEE (Symbolic virtual machine)

**Example:**
```bash
python rea.py sample.exe --analysis-types symbolic
```

### 4. Deobfuscation

**Purpose:** Detect and reverse obfuscation techniques

**Tools Used:**
- Loki (Malware classification)
- Dfsan (Data flow sanitizer)
- ML-based techniques

**Example:**
```bash
python rea.py obfuscated.exe --analysis-types deobfuscation
```

### 5. String Mining

**Purpose:** Extract and analyze strings and embedded data

**Tools Used:**
- strings (Sysinternals)
- Binwalk (Binary analysis)
- Custom algorithms

**Example:**
```bash
python rea.py sample.exe --analysis-types string_mining
```

## Configuration Examples

### 1. Basic Configuration (config.json)

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
    },
    "frida": {
      "enabled": true,
      "timeout": 60
    }
  },
  "static_analysis": {
    "enabled": true,
    "timeout": 300,
    "extract_strings": true,
    "analyze_imports": true
  },
  "output": {
    "results_dir": "results",
    "reports_dir": "reports",
    "format": "json"
  }
}
```

### 2. Custom Tool Paths

```json
{
  "tools": {
    "ghidra": {
      "enabled": true,
      "path": "/opt/ghidra/ghidra",
      "timeout": 600
    },
    "radare2": {
      "enabled": true,
      "path": "/usr/bin/r2",
      "timeout": 120
    }
  }
}
```

### 3. Performance Tuning

```json
{
  "static_analysis": {
    "timeout": 600,
    "max_file_size": 52428800
  },
  "dynamic_analysis": {
    "timeout": 300,
    "sandbox_dir": "custom_sandbox"
  },
  "symbolic_execution": {
    "timeout": 1200,
    "max_paths": 2000
  }
}
```

## Output Examples

### 1. JSON Results Structure

```json
{
  "target": "test_sample.exe",
  "timestamp": "2025-10-03T10:37:43.864198",
  "analysis_types": ["static", "dynamic", "string_mining"],
  "results": {
    "static": {
      "target": "test_sample.exe",
      "analysis_type": "static",
      "tools_used": ["capstone"],
      "results": {
        "file_analysis": {
          "size": 412,
          "file_type": "PE",
          "is_executable": true
        },
        "entropy": {
          "entropy": 3.5333,
          "is_likely_packed": false
        }
      }
    },
    "dynamic": {
      "target": "test_sample.exe",
      "analysis_type": "dynamic",
      "tools_used": [],
      "results": {
        "process_monitoring": {
          "process_info": {
            "status": "completed"
          }
        }
      }
    }
  },
  "report_path": "reports\\re_analysis_report_test_sample_20251003_103744.html"
}
```

### 2. HTML Report Features

- **Interactive Interface:** Collapsible sections for detailed results
- **Visual Indicators:** Color-coded status and findings
- **Comprehensive Data:** All analysis results in one place
- **Export Options:** JSON, summary, and detailed reports

### 3. File Structure

```
results/
├── analysis_results_20251003_103712.json
├── analysis_results_20251003_103744.json
└── analysis_results_20251003_103705.json

reports/
├── re_analysis_report_test_sample_20251003_103712.html
├── re_analysis_report_test_sample_20251003_103712.json
├── re_analysis_report_test_sample_20251003_103744.html
└── re_analysis_report_test_sample_20251003_103744.json

logs/
└── re_automation_20251003_103705.log
```

## Python API Examples

### 1. Basic Python Integration

```python
from reverse_engineering_automation import ReverseEngineeringAutomation

# Initialize the tool
re_tool = ReverseEngineeringAutomation('config.json')

# Analyze a target
results = re_tool.analyze_target('malware_sample.exe')

# Process results
if 'results' in results:
    static_results = results['results'].get('static', {})
    if 'strings' in static_results:
        strings = static_results['strings']['strings']
        print(f"Found {len(strings)} strings")
```

### 2. Custom Analysis Pipeline

```python
def custom_analysis(target_path):
    """Custom analysis pipeline"""
    re_tool = ReverseEngineeringAutomation()
    
    # Step 1: Quick scan
    quick_results = re_tool.quick_scan(target_path)
    
    # Step 2: Static analysis
    static_results = re_tool.static_analyzer.analyze(target_path)
    
    # Step 3: String mining
    string_results = re_tool.string_miner.analyze(target_path)
    
    return {
        'quick_scan': quick_results,
        'static_analysis': static_results,
        'string_mining': string_results
    }
```

### 3. Batch Processing with Python

```python
import os
from pathlib import Path

def batch_analyze(directory):
    """Analyze all files in a directory"""
    re_tool = ReverseEngineeringAutomation()
    results = {}
    
    for file_path in Path(directory).glob('*.exe'):
        print(f"Analyzing: {file_path}")
        try:
            result = re_tool.quick_scan(str(file_path))
            results[str(file_path)] = result
        except Exception as e:
            print(f"Error analyzing {file_path}: {e}")
    
    return results

# Usage
results = batch_analyze('/path/to/malware/samples')
```

### 4. Configuration Management

```python
from utils.config_manager import ConfigManager

# Load configuration
config = ConfigManager('config.json')

# Check tool availability
if config.is_tool_enabled('ghidra'):
    print("Ghidra is enabled")

# Get tool configuration
ghidra_config = config.get_tool_config('ghidra')
print(f"Ghidra timeout: {ghidra_config.get('timeout', 300)}")

# Update configuration
config.set('static_analysis.timeout', 600)
config.save_config()
```

### 5. Report Generation

```python
from utils.report_generator import ReportGenerator

# Generate reports
report_gen = ReportGenerator()
results = analyze_target('sample.exe')

# Generate different report types
html_report = report_gen.generate_report(results)
summary_report = report_gen.generate_summary_report(results)
json_report = report_gen.generate_json_report(results)

print(f"HTML report: {html_report}")
print(f"Summary report: {summary_report}")
print(f"JSON report: {json_report}")
```

## Troubleshooting Examples

### 1. Common Issues

```bash
# Tool not found error
python rea.py sample.exe
# Output: "Strings command failed: [WinError 2] The system cannot find the file specified"

# Solution: Install required tools
python scripts/install_tools.py
```

### 2. Permission Issues

```bash
# Permission denied
python rea.py sample.exe
# Output: "Permission denied"

# Solution: Run with appropriate permissions
sudo python rea.py sample.exe  # Linux/Mac
# Or run as administrator on Windows
```

### 3. Memory Issues

```bash
# Large file analysis
python rea.py large_file.exe
# Output: "Memory error"

# Solution: Use quick scan or reduce analysis scope
python rea.py large_file.exe --quick
python rea.py large_file.exe --analysis-types static
```

### 4. Timeout Issues

```json
{
  "static_analysis": {
    "timeout": 1200
  },
  "dynamic_analysis": {
    "timeout": 600
  }
}
```

## Performance Tips

### 1. Quick Assessment

```bash
# Use quick scan for initial assessment
python rea.py sample.exe --quick
```

### 2. Selective Analysis

```bash
# Analyze only what you need
python rea.py sample.exe --analysis-types static string_mining
```

### 3. Batch Processing

```bash
# Process multiple files efficiently
for file in *.exe; do python rea.py "$file" --quick; done
```

### 4. Custom Output

```bash
# Organize results by date/type
python rea.py sample.exe --output "results/$(date +%Y%m%d)"
```

## Security Considerations

### 1. Sandbox Mode

```json
{
  "security": {
    "sandbox_mode": true,
    "isolate_network": true,
    "quarantine_results": true
  }
}
```

### 2. File Permissions

```bash
# Ensure proper file permissions
chmod 600 config.json
chmod 700 results/
chmod 700 reports/
```

### 3. Network Isolation

```bash
# Analyze in isolated environment
# Use virtual machines or containers
# Disable network access during analysis
```

This comprehensive usage guide demonstrates the practical application of the Reverse Engineering Automation Tool for various analysis scenarios, from basic quick scans to comprehensive multi-type analysis workflows.
