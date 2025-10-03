# Quick Start Guide

**NTRO Approved - Government of India Project**

## Execute All Analysis at Once

### Command to run ALL analysis types:

```bash
python RevEngX.py <target_binary>
```

**This command automatically runs all 5 analysis types:**
- Static Analysis (Ghidra, Radare2, Capstone)
- Dynamic Analysis (x64dbg, QEMU, Frida)
- Symbolic Execution (Angr, KLEE)
- Deobfuscation (Loki, Dfsan, ML)
- String Mining (strings, Binwalk)

### Alternative explicit command:

```bash
python RevEngX.py <target_binary> --analysis-types static dynamic symbolic deobfuscation string_mining
```

## Quick Examples

### 1. Analyze a malware sample with all analysis types:
```bash
python rea.py malware_sample.exe
```

### 2. Quick scan for basic information:
```bash
python rea.py malware_sample.exe --quick
```

### 3. Custom output directory:
```bash
python rea.py malware_sample.exe --output /path/to/results
```

### 4. Specific analysis types only:
```bash
# Static analysis only
python rea.py malware_sample.exe --analysis-types static

# Static and dynamic analysis
python rea.py malware_sample.exe --analysis-types static dynamic

# String mining only
python rea.py malware_sample.exe --analysis-types string_mining
```

## Output

The tool generates:
- **JSON Results**: `results/analysis_results_TIMESTAMP.json`
- **HTML Report**: `reports/re_analysis_report_TARGET_TIMESTAMP.html`
- **Log Files**: `logs/re_automation_TIMESTAMP.log`

## File Renamed

The main script has been renamed from `reverse_engineering_automation.py` to `RevEngX.py` for easier usage.

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Install external tools (optional)
python scripts/install_tools.py
```

## Configuration

Edit `config.json` to customize:
- Tool paths and timeouts
- Analysis parameters
- Output directories
- Security settings

## Help

```bash
python rea.py --help
```

---

**Note**: The tool is designed to work even if some external tools are not installed. It will gracefully handle missing tools and continue with available analysis methods.
