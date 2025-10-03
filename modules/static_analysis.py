#!/usr/bin/env python3
"""
Static Analysis Module
NTRO Approved - Government of India Project

This module provides static analysis capabilities using:
- Ghidra: Framework by NSA for binary analysis and decompilation
- Radare2: Disassembling, debugging, and patching
- Capstone: Disassembly framework
"""

import os
import json
import subprocess
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
import tempfile

class StaticAnalyzer:
    """
    Static analysis engine using Ghidra, Radare2, and Capstone
    """
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger('StaticAnalyzer')
        
        # Tool paths from config
        self.ghidra_path = config.get('tools', {}).get('ghidra', {}).get('path', 'ghidra')
        self.radare2_path = config.get('tools', {}).get('radare2', {}).get('path', 'r2')
        self.capstone_available = config.get('tools', {}).get('capstone', {}).get('enabled', True)
        
        # Analysis options
        self.analysis_options = config.get('static_analysis', {})
    
    def analyze(self, target_path: str) -> Dict[str, Any]:
        """
        Perform comprehensive static analysis on target
        
        Args:
            target_path: Path to the target binary
        
        Returns:
            Dictionary containing static analysis results
        """
        self.logger.info(f"Starting static analysis of: {target_path}")
        
        results = {
            'target': target_path,
            'analysis_type': 'static',
            'tools_used': [],
            'results': {}
        }
        
        try:
            # Basic file analysis
            results['results']['file_analysis'] = self._analyze_file(target_path)
            
            # Radare2 analysis
            if self._check_tool_availability('radare2'):
                results['results']['radare2'] = self._radare2_analysis(target_path)
                results['tools_used'].append('radare2')
            
            # Ghidra analysis (if available)
            if self._check_tool_availability('ghidra'):
                results['results']['ghidra'] = self._ghidra_analysis(target_path)
                results['tools_used'].append('ghidra')
            
            # Capstone analysis
            if self.capstone_available:
                results['results']['capstone'] = self._capstone_analysis(target_path)
                results['tools_used'].append('capstone')
            
            # PE/ELF analysis
            results['results']['binary_format'] = self._analyze_binary_format(target_path)
            
            # Import/Export analysis
            results['results']['imports_exports'] = self._analyze_imports_exports(target_path)
            
            # Function discovery
            results['results']['functions'] = self._discover_functions(target_path)
            
            # String analysis
            results['results']['strings'] = self._extract_strings(target_path)
            
            # Entropy analysis
            results['results']['entropy'] = self._calculate_entropy(target_path)
            
        except Exception as e:
            self.logger.error(f"Error in static analysis: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def quick_analysis(self, target_path: str) -> Dict[str, Any]:
        """
        Perform quick static analysis using basic tools
        
        Args:
            target_path: Path to the target binary
        
        Returns:
            Dictionary containing quick analysis results
        """
        self.logger.info(f"Performing quick static analysis of: {target_path}")
        
        results = {
            'target': target_path,
            'analysis_type': 'quick_static',
            'results': {}
        }
        
        try:
            # Basic file info
            results['results']['file_info'] = self._get_basic_file_info(target_path)
            
            # Quick string extraction
            results['results']['strings'] = self._extract_strings(target_path, max_length=100)
            
            # Basic binary format analysis
            results['results']['binary_format'] = self._analyze_binary_format(target_path)
            
        except Exception as e:
            self.logger.error(f"Error in quick analysis: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def _check_tool_availability(self, tool_name: str) -> bool:
        """Check if a tool is available in the system"""
        try:
            if tool_name == 'ghidra':
                result = subprocess.run([self.ghidra_path, '--version'], 
                                      capture_output=True, text=True, timeout=10)
                return result.returncode == 0
            elif tool_name == 'radare2':
                result = subprocess.run([self.radare2_path, '--version'], 
                                      capture_output=True, text=True, timeout=10)
                return result.returncode == 0
            return False
        except:
            return False
    
    def _analyze_file(self, target_path: str) -> Dict[str, Any]:
        """Basic file analysis"""
        try:
            stat = os.stat(target_path)
            file_size = stat.st_size
            
            # Read first few bytes to determine file type
            with open(target_path, 'rb') as f:
                header = f.read(512)
            
            return {
                'size': file_size,
                'header_hex': header[:64].hex(),
                'magic_bytes': header[:4].hex(),
                'is_executable': self._is_executable(target_path),
                'file_type': self._detect_file_type(header)
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _is_executable(self, target_path: str) -> bool:
        """Check if file is executable"""
        try:
            # Check file extension
            ext = Path(target_path).suffix.lower()
            executable_extensions = ['.exe', '.dll', '.sys', '.bin', '.elf', '.so']
            
            if ext in executable_extensions:
                return True
            
            # Check file permissions (Unix-like systems)
            if os.name != 'nt':
                return os.access(target_path, os.X_OK)
            
            return False
        except:
            return False
    
    def _detect_file_type(self, header: bytes) -> str:
        """Detect file type from header bytes"""
        if len(header) < 4:
            return 'unknown'
        
        # PE signature
        if header[:2] == b'MZ':
            return 'PE'
        
        # ELF signature
        if header[:4] == b'\x7fELF':
            return 'ELF'
        
        # Mach-O signature
        if header[:4] in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', 
                         b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe']:
            return 'Mach-O'
        
        return 'unknown'
    
    def _radare2_analysis(self, target_path: str) -> Dict[str, Any]:
        """Perform analysis using Radare2"""
        try:
            results = {}
            
            # Basic info
            cmd = [self.radare2_path, '-c', 'i', '-q', target_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                results['info'] = result.stdout
            
            # Strings
            cmd = [self.radare2_path, '-c', 'iz', '-q', target_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                results['strings'] = result.stdout
            
            # Functions
            cmd = [self.radare2_path, '-c', 'afl', '-q', target_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                results['functions'] = result.stdout
            
            # Imports
            cmd = [self.radare2_path, '-c', 'ii', '-q', target_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                results['imports'] = result.stdout
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _ghidra_analysis(self, target_path: str) -> Dict[str, Any]:
        """Perform analysis using Ghidra (headless mode)"""
        try:
            # Create temporary project directory
            with tempfile.TemporaryDirectory() as temp_dir:
                project_name = f"ghidra_analysis_{Path(target_path).stem}"
                project_path = os.path.join(temp_dir, project_name)
                
                # Create Ghidra script for analysis
                script_content = '''
import json
import sys

def main():
    if currentProgram is None:
        print("No program loaded")
        return
    
    results = {}
    
    # Basic program info
    results['program_name'] = currentProgram.getName()
    results['language'] = str(currentProgram.getLanguage())
    results['processor'] = str(currentProgram.getLanguage().getProcessor())
    results['address_size'] = currentProgram.getAddressFactory().getDefaultAddressSpace().getSize()
    
    # Functions
    functions = []
    func_manager = currentProgram.getFunctionManager()
    for func in func_manager.getFunctions(True):
        func_info = {
            'name': func.getName(),
            'address': str(func.getEntryPoint()),
            'size': func.getBody().getNumAddresses()
        }
        functions.append(func_info)
    results['functions'] = functions
    
    # Strings
    strings = []
    string_manager = currentProgram.getListing().getDefinedData(True)
    for data in string_manager:
        if data.hasStringValue():
            string_info = {
                'address': str(data.getAddress()),
                'value': data.getValue()
            }
            strings.append(string_info)
    results['strings'] = strings
    
    # Output results as JSON
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
'''
                
                script_path = os.path.join(temp_dir, 'analysis.py')
                with open(script_path, 'w') as f:
                    f.write(script_content)
                
                # Run Ghidra analysis
                cmd = [
                    self.ghidra_path,
                    'headless',
                    temp_dir,
                    project_name,
                    '-import', target_path,
                    '-scriptPath', temp_dir,
                    '-postScript', 'analysis.py'
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0:
                    # Parse output for JSON results
                    output_lines = result.stdout.split('\n')
                    json_started = False
                    json_content = []
                    
                    for line in output_lines:
                        if line.strip().startswith('{'):
                            json_started = True
                        if json_started:
                            json_content.append(line)
                    
                    if json_content:
                        try:
                            return json.loads('\n'.join(json_content))
                        except:
                            pass
                
                return {'error': 'Failed to parse Ghidra output'}
                
        except Exception as e:
            return {'error': str(e)}
    
    def _capstone_analysis(self, target_path: str) -> Dict[str, Any]:
        """Perform analysis using Capstone disassembly framework"""
        try:
            # This would require the capstone Python library
            # For now, return a placeholder
            return {
                'note': 'Capstone analysis requires capstone Python library',
                'suggestion': 'Install with: pip install capstone'
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_binary_format(self, target_path: str) -> Dict[str, Any]:
        """Analyze binary format (PE, ELF, etc.)"""
        try:
            with open(target_path, 'rb') as f:
                header = f.read(1024)
            
            file_type = self._detect_file_type(header)
            
            if file_type == 'PE':
                return self._analyze_pe_format(header)
            elif file_type == 'ELF':
                return self._analyze_elf_format(header)
            else:
                return {'type': file_type, 'note': 'Format analysis not implemented'}
                
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_pe_format(self, header: bytes) -> Dict[str, Any]:
        """Analyze PE format"""
        try:
            # Basic PE analysis
            if len(header) < 64:
                return {'error': 'Header too short for PE analysis'}
            
            # DOS header
            dos_header = header[:64]
            pe_offset = int.from_bytes(dos_header[60:64], 'little')
            
            if pe_offset + 4 <= len(header):
                pe_signature = header[pe_offset:pe_offset+4]
                if pe_signature == b'PE\x00\x00':
                    return {
                        'type': 'PE',
                        'pe_offset': pe_offset,
                        'signature': pe_signature.hex(),
                        'note': 'Valid PE file detected'
                    }
            
            return {'type': 'PE', 'error': 'Invalid PE signature'}
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_elf_format(self, header: bytes) -> Dict[str, Any]:
        """Analyze ELF format"""
        try:
            if len(header) < 16:
                return {'error': 'Header too short for ELF analysis'}
            
            # ELF header analysis
            ei_class = header[4]  # 32-bit or 64-bit
            ei_data = header[5]   # Endianness
            ei_version = header[6]
            e_type = header[16]   # Executable type
            
            return {
                'type': 'ELF',
                'class': '64-bit' if ei_class == 2 else '32-bit',
                'endianness': 'big' if ei_data == 2 else 'little',
                'version': ei_version,
                'executable_type': e_type
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_imports_exports(self, target_path: str) -> Dict[str, Any]:
        """Analyze imports and exports"""
        try:
            results = {'imports': [], 'exports': []}
            
            # Try to use objdump for imports/exports
            try:
                # Imports
                cmd = ['objdump', '-p', target_path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'DLL Name:' in line:
                            dll_name = line.split('DLL Name:')[-1].strip()
                            results['imports'].append({'dll': dll_name})
            except:
                pass
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _discover_functions(self, target_path: str) -> Dict[str, Any]:
        """Discover functions in the binary"""
        try:
            functions = []
            
            # Try using nm if available
            try:
                cmd = ['nm', '-D', target_path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 3:
                                functions.append({
                                    'address': parts[0],
                                    'type': parts[1],
                                    'name': parts[2]
                                })
            except:
                pass
            
            return {'functions': functions}
            
        except Exception as e:
            return {'error': str(e)}
    
    def _extract_strings(self, target_path: str, max_length: int = 1000) -> Dict[str, Any]:
        """Extract strings from binary"""
        try:
            strings = []
            
            # Try using strings command
            try:
                cmd = ['strings', '-a', target_path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines[:max_length]:  # Limit output
                        if len(line.strip()) > 3:  # Filter short strings
                            strings.append(line.strip())
            except:
                pass
            
            return {
                'strings': strings,
                'count': len(strings)
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _calculate_entropy(self, target_path: str) -> Dict[str, Any]:
        """Calculate file entropy"""
        try:
            import math
            
            with open(target_path, 'rb') as f:
                data = f.read()
            
            if not data:
                return {'entropy': 0}
            
            # Calculate byte frequency
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Calculate entropy
            entropy = 0
            for count in byte_counts:
                if count > 0:
                    probability = count / len(data)
                    entropy -= probability * math.log2(probability)
            
            # Determine if file is likely packed/encrypted
            is_packed = entropy > 7.5
            
            return {
                'entropy': round(entropy, 4),
                'is_likely_packed': is_packed,
                'file_size': len(data)
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _get_basic_file_info(self, target_path: str) -> Dict[str, Any]:
        """Get basic file information"""
        try:
            stat = os.stat(target_path)
            return {
                'name': Path(target_path).name,
                'size': stat.st_size,
                'size_mb': round(stat.st_size / (1024 * 1024), 2),
                'modified': stat.st_mtime,
                'is_executable': self._is_executable(target_path)
            }
        except Exception as e:
            return {'error': str(e)}
