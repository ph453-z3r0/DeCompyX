# Usage Examples

**NTRO Approved - Government of India Project**

This document provides comprehensive usage examples for the Reverse Engineering Automation Tool.

## Table of Contents

1. [Basic Usage](#basic-usage)
2. [Static Analysis Examples](#static-analysis-examples)
3. [Dynamic Analysis Examples](#dynamic-analysis-examples)
4. [Symbolic Execution Examples](#symbolic-execution-examples)
5. [Deobfuscation Examples](#deobfuscation-examples)
6. [String Mining Examples](#string-mining-examples)
7. [Advanced Configuration](#advanced-configuration)
8. [Batch Processing](#batch-processing)
9. [Integration Examples](#integration-examples)

## Basic Usage

### Simple Analysis
```bash
# Analyze a single binary with all available analysis types
python RevEngX.py malware_sample.exe

# Quick scan for basic information
python rea.py malware_sample.exe --quick

# Specify output directory
python rea.py malware_sample.exe --output /path/to/results
```

### Selective Analysis
```bash
# Only static analysis
python rea.py malware_sample.exe --analysis-types static

# Static and dynamic analysis
python rea.py malware_sample.exe --analysis-types static dynamic

# All analysis types except symbolic execution
python rea.py malware_sample.exe --analysis-types static dynamic deobfuscation string_mining
```

## Static Analysis Examples

### Basic Static Analysis
```bash
# Analyze PE executable
python rea.py sample.exe --analysis-types static

# Analyze ELF binary
python rea.py sample.elf --analysis-types static

# Analyze DLL file
python rea.py library.dll --analysis-types static
```

### Expected Output
```json
{
  "target": "sample.exe",
  "analysis_type": "static",
  "tools_used": ["radare2", "ghidra", "capstone"],
  "results": {
    "file_analysis": {
      "size": 2048576,
      "header_hex": "4d5a90000300000004000000ffff0000",
      "magic_bytes": "4d5a9000",
      "is_executable": true,
      "file_type": "PE"
    },
    "functions": {
      "functions": [
        {
          "name": "main",
          "address": "0x401000",
          "size": 256
        }
      ]
    },
    "strings": {
      "strings": [
        "Hello World",
        "kernel32.dll",
        "CreateFileA"
      ],
      "count": 150
    }
  }
}
```

### Custom Static Analysis Configuration
```json
{
  "static_analysis": {
    "enabled": true,
    "timeout": 600,
    "extract_strings": true,
    "min_string_length": 6,
    "analyze_imports": true,
    "calculate_entropy": true,
    "max_file_size": 52428800
  }
}
```

## Dynamic Analysis Examples

### Basic Dynamic Analysis
```bash
# Analyze with dynamic monitoring
python rea.py malware_sample.exe --analysis-types dynamic

# Analyze with Frida instrumentation
python rea.py malware_sample.exe --analysis-types dynamic
```

### Expected Output
```json
{
  "target": "malware_sample.exe",
  "analysis_type": "dynamic",
  "tools_used": ["frida"],
  "results": {
    "process_monitoring": {
      "process_info": {
        "pid": 1234,
        "start_time": 1640995200.0,
        "status": "completed",
        "return_code": 0
      }
    },
    "network_analysis": {
      "network_connections": [
        {
          "remote_ip": "192.168.1.100",
          "remote_port": 80,
          "protocol": "TCP"
        }
      ]
    },
    "filesystem_monitoring": {
      "files_created": [
        "C:\\temp\\malware_data.txt"
      ],
      "files_modified": [
        "C:\\Windows\\System32\\config\\sam"
      ]
    }
  }
}
```

### Frida Script Example
```javascript
// Custom Frida script for API monitoring
console.log("Starting custom Frida analysis...");

// Hook file operations
var fileHooks = [
    'kernel32.dll!CreateFileA',
    'kernel32.dll!CreateFileW',
    'kernel32.dll!WriteFile',
    'kernel32.dll!ReadFile'
];

fileHooks.forEach(function(api) {
    try {
        var parts = api.split('!');
        var module = parts[0];
        var function = parts[1];
        
        var funcAddr = Module.findExportByName(module, function);
        if (funcAddr) {
            Interceptor.attach(funcAddr, {
                onEnter: function(args) {
                    console.log("[FILE] " + api + " called");
                    console.log("  Args: " + args.map(function(arg) {
                        return arg.toString();
                    }).join(', '));
                }
            });
        }
    } catch (e) {
        console.log("Failed to hook " + api + ": " + e.message);
    }
});
```

## Symbolic Execution Examples

### Basic Symbolic Execution
```bash
# Analyze with symbolic execution
python rea.py target.exe --analysis-types symbolic
```

### Expected Output
```json
{
  "target": "target.exe",
  "analysis_type": "symbolic_execution",
  "tools_used": ["angr"],
  "results": {
    "angr": {
      "project_info": {
        "arch": "x86",
        "entry_point": "0x401000",
        "base_addr": "0x400000"
      },
      "exploration_info": {
        "paths_explored": 150,
        "active_states": 5,
        "deadended_states": 145,
        "errored_states": 0
      },
      "vulnerabilities": [
        {
          "type": "potential_buffer_overflow",
          "state": "0x401234"
        }
      ]
    }
  }
}
```

### Angr Configuration
```python
# Custom Angr analysis script
import angr

# Load project
project = angr.Project('target.exe', auto_load_libs=False)

# Create initial state
initial_state = project.factory.entry_state()

# Create simulation manager
simgr = project.factory.simulation_manager(initial_state)

# Explore paths
simgr.explore(find=lambda s: b"success" in s.posix.dumps(1),
              avoid=lambda s: b"failure" in s.posix.dumps(1))

# Print results
if simgr.found:
    print("Found successful path!")
    print("Input:", simgr.found[0].posix.dumps(0))
else:
    print("No successful path found")
```

## Deobfuscation Examples

### Basic Deobfuscation
```bash
# Analyze obfuscated binary
python rea.py obfuscated.exe --analysis-types deobfuscation
```

### Expected Output
```json
{
  "target": "obfuscated.exe",
  "analysis_type": "deobfuscation",
  "tools_used": ["ml"],
  "results": {
    "obfuscation_detection": {
      "obfuscation_detected": true,
      "obfuscation_types": ["high_entropy", "string_obfuscation"],
      "confidence_score": 0.85,
      "indicators": [
        "High entropy: 7.89",
        "XOR operations detected",
        "Indirect jumps found"
      ]
    },
    "string_deobfuscation": {
      "strings_found": [
        {
          "offset": 1024,
          "length": 32,
          "content": "encrypted_string_here"
        }
      ],
      "deobfuscated_strings": [
        {
          "original": "encrypted_string_here",
          "deobfuscated": "Hello World",
          "method": "_try_xor_deobfuscation"
        }
      ]
    }
  }
}
```

### Custom Deobfuscation Patterns
```python
# Custom deobfuscation patterns
obfuscation_patterns = {
    'string_obfuscation': [
        r'xor\s+[a-zA-Z0-9_]+\s*,\s*[a-zA-Z0-9_]+',
        r'add\s+[a-zA-Z0-9_]+\s*,\s*[a-zA-Z0-9_]+',
        r'sub\s+[a-zA-Z0-9_]+\s*,\s*[a-zA-Z0-9_]+'
    ],
    'control_flow_obfuscation': [
        r'jmp\s+[a-zA-Z0-9_]+',
        r'call\s+[a-zA-Z0-9_]+',
        r'ret\s+[a-zA-Z0-9_]+'
    ],
    'packing_indicators': [
        r'UPX',
        r'PECompact',
        r'ASPack'
    ]
}
```

## String Mining Examples

### Basic String Mining
```bash
# Extract strings and analyze patterns
python rea.py sample.exe --analysis-types string_mining
```

### Expected Output
```json
{
  "target": "sample.exe",
  "analysis_type": "string_mining",
  "tools_used": ["strings", "binwalk"],
  "results": {
    "basic_strings": {
      "strings": [
        "Hello World",
        "kernel32.dll",
        "CreateFileA",
        "https://malicious-site.com"
      ],
      "count": 250
    },
    "pattern_analysis": {
      "patterns_found": {
        "urls": [
          "https://malicious-site.com",
          "http://command-server.net"
        ],
        "email_addresses": [
          "admin@malicious-site.com"
        ],
        "ip_addresses": [
          "192.168.1.100",
          "10.0.0.1"
        ]
      }
    },
    "crypto_material": {
      "crypto_indicators": [
        "AES",
        "RSA",
        "MD5"
      ],
      "crypto_keys": [
        "a1b2c3d4e5f6789012345678901234567890abcdef"
      ]
    }
  }
}
```

### Custom String Patterns
```python
# Custom string patterns for analysis
custom_patterns = {
    'malware_indicators': [
        r'botnet|trojan|virus|malware',
        r'backdoor|keylog|spy',
        r'ransom|encrypt|decrypt'
    ],
    'network_indicators': [
        r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]+',
        r'https?://[^\s<>"{}|\\^`\[\]]+'
    ],
    'file_indicators': [
        r'[a-zA-Z]:\\[^<>:"/\\|?*\x00-\x1f]*',
        r'/[^<>:"/\\|?*\x00-\x1f]*'
    ]
}
```

## Advanced Configuration

### Custom Analysis Configuration
```json
{
  "static_analysis": {
    "enabled": true,
    "timeout": 600,
    "extract_strings": true,
    "min_string_length": 6,
    "analyze_imports": true,
    "calculate_entropy": true,
    "max_file_size": 52428800
  },
  "dynamic_analysis": {
    "enabled": true,
    "timeout": 300,
    "sandbox_dir": "custom_sandbox",
    "monitor_processes": true,
    "monitor_network": true,
    "monitor_filesystem": true
  },
  "symbolic_execution": {
    "enabled": true,
    "timeout": 1200,
    "max_paths": 2000,
    "vulnerability_detection": true
  }
}
```

### Tool-Specific Configuration
```json
{
  "tools": {
    "ghidra": {
      "enabled": true,
      "path": "/opt/ghidra/ghidra",
      "headless": true,
      "timeout": 600
    },
    "radare2": {
      "enabled": true,
      "path": "/usr/bin/r2",
      "timeout": 120
    },
    "frida": {
      "enabled": true,
      "timeout": 120,
      "script_timeout": 60
    }
  }
}
```

## Batch Processing

### Process Multiple Files
```bash
#!/bin/bash
# Batch processing script

TARGET_DIR="/path/to/malware/samples"
OUTPUT_DIR="/path/to/results"

for file in "$TARGET_DIR"/*; do
    if [ -f "$file" ]; then
        echo "Processing: $file"
        python rea.py "$file" --output "$OUTPUT_DIR"
    fi
done
```

### Python Batch Processing
```python
import os
import subprocess
from pathlib import Path

def batch_process(directory, output_dir):
    """Process all files in a directory"""
    for file_path in Path(directory).glob('*'):
        if file_path.is_file():
            print(f"Processing: {file_path}")
            try:
                subprocess.run([
                    'python', 'reverse_engineering_automation.py',
                    str(file_path), '--output', output_dir
                ], check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error processing {file_path}: {e}")

# Usage
batch_process('/path/to/samples', '/path/to/results')
```

## Integration Examples

### Python API Integration
```python
from reverse_engineering_automation import ReverseEngineeringAutomation

# Initialize tool
re_tool = ReverseEngineeringAutomation('config.json')

# Analyze target
results = re_tool.analyze_target('malware_sample.exe')

# Process results
if 'results' in results:
    static_results = results['results'].get('static', {})
    if 'strings' in static_results:
        strings = static_results['strings']['strings']
        print(f"Found {len(strings)} strings")
        
        # Filter suspicious strings
        suspicious = [s for s in strings if 'malware' in s.lower()]
        print(f"Suspicious strings: {suspicious}")
```

### Custom Analysis Pipeline
```python
def custom_analysis_pipeline(target_path):
    """Custom analysis pipeline"""
    re_tool = ReverseEngineeringAutomation()
    
    # Step 1: Quick scan
    quick_results = re_tool.quick_scan(target_path)
    
    # Step 2: Static analysis
    static_results = re_tool.static_analyzer.analyze(target_path)
    
    # Step 3: String mining
    string_results = re_tool.string_miner.analyze(target_path)
    
    # Step 4: Combine results
    combined_results = {
        'quick_scan': quick_results,
        'static_analysis': static_results,
        'string_mining': string_results
    }
    
    return combined_results
```

### Report Integration
```python
from utils.report_generator import ReportGenerator

# Generate custom report
report_gen = ReportGenerator()
results = analyze_target('sample.exe')
report_path = report_gen.generate_report(results)

# Generate summary
summary_path = report_gen.generate_summary_report(results)

# Generate JSON
json_path = report_gen.generate_json_report(results)
```

## Troubleshooting Examples

### Common Issues and Solutions

1. **Tool Not Found**
```bash
# Check tool availability
python -c "import subprocess; subprocess.run(['ghidra', '--version'])"

# Install missing tools
python scripts/install_tools.py
```

2. **Permission Issues**
```bash
# Run with appropriate permissions
sudo python rea.py target.exe

# Check file permissions
ls -la target.exe
```

3. **Memory Issues**
```bash
# Use smaller analysis scope
python rea.py target.exe --analysis-types static

# Increase system memory
# Edit config.json to reduce max_paths and timeout values
```

4. **Timeout Issues**
```json
{
  "static_analysis": {
    "timeout": 1200
  },
  "dynamic_analysis": {
    "timeout": 600
  },
  "symbolic_execution": {
    "timeout": 1800
  }
}
```

## Performance Optimization

### Large File Analysis
```json
{
  "static_analysis": {
    "max_file_size": 104857600,
    "timeout": 1800,
    "extract_strings": true,
    "max_strings": 50000
  }
}
```

### Parallel Processing
```python
import concurrent.futures
import multiprocessing

def analyze_file(file_path):
    """Analyze a single file"""
    re_tool = ReverseEngineeringAutomation()
    return re_tool.analyze_target(file_path)

def parallel_analysis(file_list):
    """Analyze multiple files in parallel"""
    with concurrent.futures.ProcessPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(analyze_file, f) for f in file_list]
        results = [f.result() for f in futures]
    return results
```

This comprehensive usage guide should help you effectively use the Reverse Engineering Automation Tool for various analysis scenarios.
