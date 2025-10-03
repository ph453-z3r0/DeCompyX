# API Reference

**NTRO Approved - Government of India Project**

This document provides detailed API reference for the Reverse Engineering Automation Tool.

## Table of Contents

1. [Main Automation Class](#main-automation-class)
2. [Static Analysis Module](#static-analysis-module)
3. [Dynamic Analysis Module](#dynamic-analysis-module)
4. [Symbolic Execution Module](#symbolic-execution-module)
5. [Deobfuscation Module](#deobfuscation-module)
6. [String Mining Module](#string-mining-module)
7. [Utility Classes](#utility-classes)
8. [Configuration Management](#configuration-management)
9. [Report Generation](#report-generation)

## Main Automation Class

### `ReverseEngineeringAutomation`

Main class that orchestrates all reverse engineering tasks.

```python
from rea import ReverseEngineeringAutomation

# Initialize
re_tool = ReverseEngineeringAutomation(config_file="config.json")

# Analyze target
results = re_tool.analyze_target(target_path, analysis_types=None)

# Quick scan
quick_results = re_tool.quick_scan(target_path)
```

#### Methods

##### `__init__(self, config_file: str = "config.json")`

Initialize the automation tool with configuration.

**Parameters:**
- `config_file` (str): Path to configuration file

**Returns:**
- `ReverseEngineeringAutomation`: Initialized automation tool

##### `analyze_target(self, target_path: str, analysis_types: List[str] = None) -> Dict[str, Any]`

Perform comprehensive reverse engineering analysis on target.

**Parameters:**
- `target_path` (str): Path to the target binary/executable
- `analysis_types` (List[str], optional): List of analysis types to perform

**Returns:**
- `Dict[str, Any]`: Dictionary containing all analysis results

**Example:**
```python
# Analyze with all available analysis types
results = re_tool.analyze_target("malware.exe")

# Analyze with specific types
results = re_tool.analyze_target("malware.exe", ["static", "dynamic"])
```

##### `quick_scan(self, target_path: str) -> Dict[str, Any]`

Perform a quick scan using basic tools.

**Parameters:**
- `target_path` (str): Path to the target binary

**Returns:**
- `Dict[str, Any]`: Dictionary containing quick scan results

**Example:**
```python
quick_results = re_tool.quick_scan("sample.exe")
print(f"File size: {quick_results['results']['file_info']['size']}")
```

## Static Analysis Module

### `StaticAnalyzer`

Provides static analysis capabilities using Ghidra, Radare2, and Capstone.

```python
from modules.static_analysis import StaticAnalyzer
from utils.config_manager import ConfigManager

config = ConfigManager()
analyzer = StaticAnalyzer(config)
```

#### Methods

##### `analyze(self, target_path: str) -> Dict[str, Any]`

Perform comprehensive static analysis on target.

**Parameters:**
- `target_path` (str): Path to the target binary

**Returns:**
- `Dict[str, Any]`: Dictionary containing static analysis results

**Example:**
```python
results = analyzer.analyze("target.exe")
print(f"Functions found: {len(results['results']['functions']['functions'])}")
```

##### `quick_analysis(self, target_path: str) -> Dict[str, Any]`

Perform quick static analysis using basic tools.

**Parameters:**
- `target_path` (str): Path to the target binary

**Returns:**
- `Dict[str, Any]`: Dictionary containing quick analysis results

**Example:**
```python
quick_results = analyzer.quick_analysis("target.exe")
print(f"File type: {quick_results['results']['binary_format']['type']}")
```

#### Private Methods

##### `_analyze_file(self, target_path: str) -> Dict[str, Any]`

Basic file analysis including size, header, and magic bytes.

##### `_radare2_analysis(self, target_path: str) -> Dict[str, Any]`

Perform analysis using Radare2.

##### `_ghidra_analysis(self, target_path: str) -> Dict[str, Any]`

Perform analysis using Ghidra in headless mode.

##### `_calculate_entropy(self, target_path: str) -> Dict[str, Any]`

Calculate file entropy for packing detection.

## Dynamic Analysis Module

### `DynamicAnalyzer`

Provides dynamic analysis capabilities using x64dbg, QEMU, and Frida.

```python
from modules.dynamic_analysis import DynamicAnalyzer
from utils.config_manager import ConfigManager

config = ConfigManager()
analyzer = DynamicAnalyzer(config)
```

#### Methods

##### `analyze(self, target_path: str) -> Dict[str, Any]`

Perform comprehensive dynamic analysis on target.

**Parameters:**
- `target_path` (str): Path to the target binary

**Returns:**
- `Dict[str, Any]`: Dictionary containing dynamic analysis results

**Example:**
```python
results = analyzer.analyze("malware.exe")
process_info = results['results']['process_monitoring']['process_info']
print(f"Process PID: {process_info['pid']}")
```

#### Private Methods

##### `_pre_execution_analysis(self, target_path: str) -> Dict[str, Any]`

Analyze target before execution.

##### `_frida_analysis(self, target_path: str) -> Dict[str, Any]`

Perform analysis using Frida instrumentation.

##### `_monitor_process_execution(self, target_path: str) -> Dict[str, Any]`

Monitor process execution and behavior.

##### `_analyze_network_behavior(self, target_path: str) -> Dict[str, Any]`

Analyze network behavior during execution.

## Symbolic Execution Module

### `SymbolicExecutor`

Provides symbolic execution capabilities using Angr and KLEE.

```python
from modules.symbolic_execution import SymbolicExecutor
from utils.config_manager import ConfigManager

config = ConfigManager()
executor = SymbolicExecutor(config)
```

#### Methods

##### `analyze(self, target_path: str) -> Dict[str, Any]`

Perform symbolic execution analysis on target.

**Parameters:**
- `target_path` (str): Path to the target binary

**Returns:**
- `Dict[str, Any]`: Dictionary containing symbolic execution results

**Example:**
```python
results = executor.analyze("target.exe")
angr_results = results['results']['angr']
print(f"Paths explored: {angr_results['exploration_info']['paths_explored']}")
```

#### Private Methods

##### `_angr_analysis(self, target_path: str) -> Dict[str, Any]`

Perform analysis using Angr framework.

##### `_klee_analysis(self, target_path: str) -> Dict[str, Any]`

Perform analysis using KLEE symbolic virtual machine.

##### `_detect_vulnerabilities(self, target_path: str) -> Dict[str, Any]`

Detect vulnerabilities using symbolic execution.

## Deobfuscation Module

### `DeobfuscationEngine`

Provides automated deobfuscation capabilities using Loki, Dfsan, and ML techniques.

```python
from modules.deobfuscation import DeobfuscationEngine
from utils.config_manager import ConfigManager

config = ConfigManager()
engine = DeobfuscationEngine(config)
```

#### Methods

##### `analyze(self, target_path: str) -> Dict[str, Any]`

Perform automated deobfuscation analysis on target.

**Parameters:**
- `target_path` (str): Path to the target binary

**Returns:**
- `Dict[str, Any]`: Dictionary containing deobfuscation results

**Example:**
```python
results = engine.analyze("obfuscated.exe")
obfuscation = results['results']['obfuscation_detection']
print(f"Obfuscation detected: {obfuscation['obfuscation_detected']}")
```

#### Private Methods

##### `_detect_obfuscation(self, target_path: str) -> Dict[str, Any]`

Detect obfuscation techniques in the target.

##### `_loki_analysis(self, target_path: str) -> Dict[str, Any]`

Perform analysis using Loki malware classification.

##### `_pattern_based_deobfuscation(self, target_path: str) -> Dict[str, Any]`

Perform pattern-based deobfuscation.

##### `_deobfuscate_strings(self, target_path: str) -> Dict[str, Any]`

Deobfuscate strings in the target.

## String Mining Module

### `StringMiner`

Provides string and data mining capabilities using strings, Binwalk, and custom algorithms.

```python
from modules.string_mining import StringMiner
from utils.config_manager import ConfigManager

config = ConfigManager()
miner = StringMiner(config)
```

#### Methods

##### `analyze(self, target_path: str) -> Dict[str, Any]`

Perform comprehensive string and data mining analysis on target.

**Parameters:**
- `target_path` (str): Path to the target binary

**Returns:**
- `Dict[str, Any]`: Dictionary containing string mining results

**Example:**
```python
results = miner.analyze("sample.exe")
strings = results['results']['basic_strings']['strings']
print(f"Found {len(strings)} strings")
```

##### `extract_strings(self, target_path: str, max_length: int = 1000) -> Dict[str, Any]`

Extract basic strings from target.

**Parameters:**
- `target_path` (str): Path to the target binary
- `max_length` (int): Maximum number of strings to extract

**Returns:**
- `Dict[str, Any]`: Dictionary containing extracted strings

**Example:**
```python
strings_result = miner.extract_strings("sample.exe", max_length=500)
print(f"Extracted {strings_result['count']} strings")
```

#### Private Methods

##### `_extract_with_strings_command(self, target_path: str) -> List[str]`

Extract strings using the strings command.

##### `_extract_with_custom_method(self, target_path: str) -> List[str]`

Extract strings using custom method.

##### `_categorize_strings(self, strings: List[str]) -> Dict[str, List[str]]`

Categorize strings by type (URLs, emails, IPs, etc.).

##### `_find_suspicious_strings(self, strings: List[str]) -> List[Dict[str, Any]]`

Find suspicious strings in the extracted data.

## Utility Classes

### `ConfigManager`

Manages configuration for the reverse engineering automation tool.

```python
from utils.config_manager import ConfigManager

config = ConfigManager("config.json")
```

#### Methods

##### `get(self, key: str, default: Any = None) -> Any`

Get configuration value by key (supports dot notation).

**Parameters:**
- `key` (str): Configuration key (e.g., "tools.ghidra.enabled")
- `default` (Any): Default value if key not found

**Returns:**
- `Any`: Configuration value

**Example:**
```python
ghidra_enabled = config.get("tools.ghidra.enabled", False)
timeout = config.get("static_analysis.timeout", 300)
```

##### `set(self, key: str, value: Any)`

Set configuration value by key (supports dot notation).

**Parameters:**
- `key` (str): Configuration key
- `value` (Any): Value to set

**Example:**
```python
config.set("tools.ghidra.timeout", 600)
config.set("static_analysis.enabled", True)
```

##### `save_config(self)`

Save configuration to file.

##### `validate_config(self) -> List[str]`

Validate configuration and return list of issues.

**Returns:**
- `List[str]`: List of validation issues

**Example:**
```python
issues = config.validate_config()
if issues:
    print("Configuration issues:", issues)
```

##### `get_tool_config(self, tool_name: str) -> Dict[str, Any]`

Get configuration for a specific tool.

**Parameters:**
- `tool_name` (str): Name of the tool

**Returns:**
- `Dict[str, Any]`: Tool configuration

**Example:**
```python
ghidra_config = config.get_tool_config("ghidra")
print(f"Ghidra timeout: {ghidra_config.get('timeout', 300)}")
```

##### `is_tool_enabled(self, tool_name: str) -> bool`

Check if a tool is enabled.

**Parameters:**
- `tool_name` (str): Name of the tool

**Returns:**
- `bool`: True if tool is enabled

**Example:**
```python
if config.is_tool_enabled("ghidra"):
    print("Ghidra is enabled")
```

### `ReportGenerator`

Generates comprehensive reports from reverse engineering analysis results.

```python
from utils.report_generator import ReportGenerator

report_gen = ReportGenerator()
```

#### Methods

##### `generate_report(self, analysis_results: Dict[str, Any]) -> str`

Generate comprehensive report from analysis results.

**Parameters:**
- `analysis_results` (Dict[str, Any]): Analysis results

**Returns:**
- `str`: Path to generated report file

**Example:**
```python
results = analyze_target("sample.exe")
report_path = report_gen.generate_report(results)
print(f"Report saved to: {report_path}")
```

##### `generate_summary_report(self, analysis_results: Dict[str, Any]) -> str`

Generate a summary report.

**Parameters:**
- `analysis_results` (Dict[str, Any]): Analysis results

**Returns:**
- `str`: Path to generated summary report

**Example:**
```python
summary_path = report_gen.generate_summary_report(results)
print(f"Summary saved to: {summary_path}")
```

##### `generate_json_report(self, analysis_results: Dict[str, Any]) -> str`

Generate JSON report.

**Parameters:**
- `analysis_results` (Dict[str, Any]): Analysis results

**Returns:**
- `str`: Path to generated JSON report

**Example:**
```python
json_path = report_gen.generate_json_report(results)
print(f"JSON report saved to: {json_path}")
```

## Configuration Management

### Configuration Structure

The configuration file (`config.json`) contains the following sections:

```json
{
  "project_info": {
    "name": "Reverse Engineering Automation Tool",
    "version": "1.0.0",
    "organization": "NTRO - Government of India"
  },
  "tools": {
    "ghidra": {
      "enabled": true,
      "path": "ghidra",
      "timeout": 300
    }
  },
  "static_analysis": {
    "enabled": true,
    "timeout": 300,
    "extract_strings": true
  },
  "output": {
    "results_dir": "results",
    "reports_dir": "reports"
  }
}
```

### Tool Configuration

Each tool can be configured with the following options:

- `enabled` (bool): Whether the tool is enabled
- `path` (str): Path to the tool executable
- `timeout` (int): Timeout in seconds
- Additional tool-specific options

### Analysis Configuration

Each analysis type can be configured with:

- `enabled` (bool): Whether the analysis is enabled
- `timeout` (int): Timeout in seconds
- Analysis-specific options

## Report Generation

### HTML Report Structure

The HTML report includes:

- Header with project information
- Analysis summary
- Detailed results for each analysis type
- Interactive collapsible sections
- Error reporting

### JSON Report Structure

The JSON report contains:

- Complete analysis results
- Metadata (timestamp, target, analysis types)
- Structured data for programmatic processing

### Summary Report Structure

The summary report provides:

- Text-based overview
- Key findings
- Statistics
- Human-readable format

## Error Handling

### Common Exceptions

- `FileNotFoundError`: Target file not found
- `subprocess.TimeoutExpired`: Tool execution timeout
- `ImportError`: Required Python package not available
- `PermissionError`: Insufficient permissions

### Error Response Format

```json
{
  "error": "Error message",
  "error_type": "ExceptionType",
  "timestamp": "2023-01-01T00:00:00Z"
}
```

## Logging

### Log Levels

- `DEBUG`: Detailed debugging information
- `INFO`: General information
- `WARNING`: Warning messages
- `ERROR`: Error messages
- `CRITICAL`: Critical errors

### Log Configuration

```json
{
  "logging": {
    "level": "INFO",
    "file_logging": true,
    "console_logging": true,
    "max_file_size": 10485760,
    "backup_count": 5
  }
}
```

## Performance Considerations

### Memory Usage

- Large binaries may require significant memory
- Consider using `max_file_size` configuration
- Monitor memory usage during analysis

### Timeout Configuration

- Set appropriate timeouts for each analysis type
- Consider system performance and file size
- Use `quick_scan` for initial assessment

### Parallel Processing

- Multiple analysis types can run in parallel
- Consider system resources when configuring
- Use appropriate worker limits

This API reference provides comprehensive documentation for all classes, methods, and configuration options available in the Reverse Engineering Automation Tool.
