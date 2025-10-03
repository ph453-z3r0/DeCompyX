#!/usr/bin/env python3
"""
Automated Deobfuscation Module
NTRO Approved - Government of India Project

This module provides automated deobfuscation capabilities using:
- Loki: Automatic malware classification and deobfuscation toolkit
- Dfsan: Data flow sanitizer framework for dynamic taint analysis
- Machine Learning: Pattern recognition for obfuscation detection
"""

import os
import json
import subprocess
import logging
import tempfile
import re
from pathlib import Path
from typing import Dict, List, Any, Optional
import hashlib
import math

class DeobfuscationEngine:
    """
    Automated deobfuscation engine using Loki, Dfsan, and ML techniques
    """
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger('DeobfuscationEngine')
        
        # Tool paths from config
        self.loki_path = config.get('tools', {}).get('loki', {}).get('path', 'loki.py')
        self.dfsan_available = config.get('tools', {}).get('dfsan', {}).get('enabled', True)
        self.ml_enabled = config.get('tools', {}).get('ml_deobfuscation', {}).get('enabled', True)
        
        # Analysis options
        self.analysis_options = config.get('deobfuscation', {})
        self.timeout = self.analysis_options.get('timeout', 300)  # 5 minutes default
        
        # Results directory
        self.results_dir = self.analysis_options.get('results_dir', 'deobfuscation_results')
        os.makedirs(self.results_dir, exist_ok=True)
        
        # Obfuscation patterns
        self.obfuscation_patterns = self._load_obfuscation_patterns()
    
    def analyze(self, target_path: str) -> Dict[str, Any]:
        """
        Perform automated deobfuscation analysis on target
        
        Args:
            target_path: Path to the target binary
        
        Returns:
            Dictionary containing deobfuscation results
        """
        self.logger.info(f"Starting deobfuscation analysis of: {target_path}")
        
        results = {
            'target': target_path,
            'analysis_type': 'deobfuscation',
            'tools_used': [],
            'results': {}
        }
        
        try:
            # Obfuscation detection
            results['results']['obfuscation_detection'] = self._detect_obfuscation(target_path)
            
            # Loki analysis (if available)
            if self._check_tool_availability('loki'):
                results['results']['loki'] = self._loki_analysis(target_path)
                results['tools_used'].append('loki')
            
            # Dfsan analysis (if available)
            if self.dfsan_available:
                results['results']['dfsan'] = self._dfsan_analysis(target_path)
                results['tools_used'].append('dfsan')
            
            # Machine learning analysis
            if self.ml_enabled:
                results['results']['ml_analysis'] = self._ml_deobfuscation(target_path)
                results['tools_used'].append('ml')
            
            # Pattern-based deobfuscation
            results['results']['pattern_deobfuscation'] = self._pattern_based_deobfuscation(target_path)
            
            # String deobfuscation
            results['results']['string_deobfuscation'] = self._deobfuscate_strings(target_path)
            
            # Control flow deobfuscation
            results['results']['control_flow_deobfuscation'] = self._deobfuscate_control_flow(target_path)
            
            # Anti-analysis detection
            results['results']['anti_analysis'] = self._detect_anti_analysis(target_path)
            
        except Exception as e:
            self.logger.error(f"Error in deobfuscation analysis: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def _check_tool_availability(self, tool_name: str) -> bool:
        """Check if a tool is available in the system"""
        try:
            if tool_name == 'loki':
                return os.path.exists(self.loki_path)
            return False
        except:
            return False
    
    def _load_obfuscation_patterns(self) -> Dict[str, List[str]]:
        """Load obfuscation patterns for detection"""
        return {
            'string_obfuscation': [
                r'xor\s+[a-zA-Z0-9_]+\s*,\s*[a-zA-Z0-9_]+',  # XOR operations
                r'add\s+[a-zA-Z0-9_]+\s*,\s*[a-zA-Z0-9_]+',  # ADD operations
                r'sub\s+[a-zA-Z0-9_]+\s*,\s*[a-zA-Z0-9_]+',  # SUB operations
                r'rol\s+[a-zA-Z0-9_]+\s*,\s*[a-zA-Z0-9_]+',  # ROL operations
                r'ror\s+[a-zA-Z0-9_]+\s*,\s*[a-zA-Z0-9_]+',  # ROR operations
            ],
            'control_flow_obfuscation': [
                r'jmp\s+[a-zA-Z0-9_]+',  # Indirect jumps
                r'call\s+[a-zA-Z0-9_]+',  # Indirect calls
                r'ret\s+[a-zA-Z0-9_]+',   # Indirect returns
            ],
            'packing_indicators': [
                r'UPX',  # UPX packer
                r'PECompact',  # PECompact packer
                r'ASPack',  # ASPack packer
                r'FSG',  # FSG packer
                r'MEW',  # MEW packer
            ],
            'anti_debugging': [
                r'IsDebuggerPresent',
                r'CheckRemoteDebuggerPresent',
                r'OutputDebugString',
                r'GetTickCount',
                r'QueryPerformanceCounter',
            ],
            'anti_vm': [
                r'VMware',
                r'VirtualBox',
                r'QEMU',
                r'Xen',
                r'Hyper-V',
            ]
        }
    
    def _detect_obfuscation(self, target_path: str) -> Dict[str, Any]:
        """Detect obfuscation techniques in the target"""
        try:
            results = {
                'obfuscation_detected': False,
                'obfuscation_types': [],
                'confidence_score': 0.0,
                'indicators': []
            }
            
            # Read file content
            with open(target_path, 'rb') as f:
                content = f.read()
            
            # Check for packing indicators
            content_str = content.decode('utf-8', errors='ignore')
            
            for category, patterns in self.obfuscation_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content_str, re.IGNORECASE)
                    if matches:
                        results['obfuscation_detected'] = True
                        results['obfuscation_types'].append(category)
                        results['indicators'].extend(matches)
            
            # Calculate entropy to detect packing/encryption
            entropy = self._calculate_entropy(content)
            if entropy > 7.5:
                results['obfuscation_detected'] = True
                results['obfuscation_types'].append('high_entropy')
                results['indicators'].append(f'High entropy: {entropy:.2f}')
            
            # Check for suspicious import patterns
            suspicious_imports = self._check_suspicious_imports(content_str)
            if suspicious_imports:
                results['obfuscation_detected'] = True
                results['obfuscation_types'].append('suspicious_imports')
                results['indicators'].extend(suspicious_imports)
            
            # Calculate confidence score
            results['confidence_score'] = self._calculate_obfuscation_confidence(results)
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        # Calculate byte frequency
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                probability = count / len(data)
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _check_suspicious_imports(self, content: str) -> List[str]:
        """Check for suspicious import patterns"""
        suspicious_imports = []
        
        # Common suspicious imports
        suspicious_patterns = [
            'VirtualAlloc',
            'VirtualProtect',
            'WriteProcessMemory',
            'ReadProcessMemory',
            'CreateRemoteThread',
            'SetWindowsHookEx',
            'UnhookWindowsHookEx',
            'GetProcAddress',
            'LoadLibrary',
            'GetModuleHandle'
        ]
        
        for pattern in suspicious_patterns:
            if pattern in content:
                suspicious_imports.append(pattern)
        
        return suspicious_imports
    
    def _calculate_obfuscation_confidence(self, results: Dict[str, Any]) -> float:
        """Calculate confidence score for obfuscation detection"""
        confidence = 0.0
        
        # Base score for obfuscation detection
        if results['obfuscation_detected']:
            confidence += 0.3
        
        # Score based on number of obfuscation types
        confidence += min(len(results['obfuscation_types']) * 0.2, 0.4)
        
        # Score based on number of indicators
        confidence += min(len(results['indicators']) * 0.05, 0.3)
        
        return min(confidence, 1.0)
    
    def _loki_analysis(self, target_path: str) -> Dict[str, Any]:
        """Perform analysis using Loki"""
        try:
            results = {}
            
            # Create temporary directory for Loki analysis
            with tempfile.TemporaryDirectory() as temp_dir:
                # Run Loki analysis
                cmd = ['python', self.loki_path, '-p', target_path, '--noprocscan', '--nolevcheck']
                
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
                    
                    if result.returncode == 0:
                        results['output'] = result.stdout
                        results['status'] = 'completed'
                        
                        # Parse Loki output for indicators
                        indicators = []
                        lines = result.stdout.split('\n')
                        for line in lines:
                            if 'ALERT' in line or 'WARNING' in line:
                                indicators.append(line.strip())
                        
                        results['indicators'] = indicators
                    else:
                        results['error'] = result.stderr
                        results['status'] = 'failed'
                
                except subprocess.TimeoutExpired:
                    results['error'] = 'Loki analysis timed out'
                    results['status'] = 'timeout'
                except Exception as e:
                    results['error'] = str(e)
                    results['status'] = 'error'
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _dfsan_analysis(self, target_path: str) -> Dict[str, Any]:
        """Perform analysis using Dfsan"""
        try:
            results = {}
            
            # Dfsan requires compilation with sanitizer flags
            # This is a simplified example - in practice, you'd need proper setup
            
            results['note'] = 'Dfsan analysis requires compilation with sanitizer flags'
            results['suggestion'] = 'Compile target with -fsanitize=dataflow flag'
            
            # Example of how Dfsan would be used:
            # 1. Compile target with Dfsan: clang -fsanitize=dataflow target.c -o target
            # 2. Run with Dfsan: ./target
            # 3. Analyze taint propagation reports
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _ml_deobfuscation(self, target_path: str) -> Dict[str, Any]:
        """Perform ML-based deobfuscation"""
        try:
            results = {
                'ml_models_used': [],
                'deobfuscation_attempts': [],
                'success_rate': 0.0
            }
            
            # This would typically use machine learning models trained on obfuscated code
            # For now, we'll provide a framework
            
            results['note'] = 'ML deobfuscation requires trained models'
            results['suggested_models'] = [
                'LSTM for sequence deobfuscation',
                'CNN for pattern recognition',
                'Transformer for code understanding'
            ]
            
            # Example ML-based deobfuscation techniques:
            # 1. String deobfuscation using pattern recognition
            # 2. Control flow deobfuscation using graph neural networks
            # 3. API call deobfuscation using sequence models
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _pattern_based_deobfuscation(self, target_path: str) -> Dict[str, Any]:
        """Perform pattern-based deobfuscation"""
        try:
            results = {
                'patterns_identified': [],
                'deobfuscation_attempts': [],
                'successful_deobfuscations': []
            }
            
            # Read file content
            with open(target_path, 'rb') as f:
                content = f.read()
            
            # Identify common obfuscation patterns
            patterns = self._identify_obfuscation_patterns(content)
            results['patterns_identified'] = patterns
            
            # Attempt deobfuscation for each pattern
            for pattern in patterns:
                deobfuscation_result = self._attempt_pattern_deobfuscation(content, pattern)
                results['deobfuscation_attempts'].append(deobfuscation_result)
                
                if deobfuscation_result['success']:
                    results['successful_deobfuscations'].append(deobfuscation_result)
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _identify_obfuscation_patterns(self, content: bytes) -> List[Dict[str, Any]]:
        """Identify obfuscation patterns in content"""
        patterns = []
        
        # Look for XOR patterns
        xor_patterns = self._find_xor_patterns(content)
        if xor_patterns:
            patterns.append({
                'type': 'xor_obfuscation',
                'count': len(xor_patterns),
                'patterns': xor_patterns
            })
        
        # Look for string obfuscation
        string_patterns = self._find_string_obfuscation(content)
        if string_patterns:
            patterns.append({
                'type': 'string_obfuscation',
                'count': len(string_patterns),
                'patterns': string_patterns
            })
        
        return patterns
    
    def _find_xor_patterns(self, content: bytes) -> List[Dict[str, Any]]:
        """Find XOR obfuscation patterns"""
        patterns = []
        
        # Look for common XOR patterns
        # This is a simplified example - in practice, you'd use more sophisticated analysis
        
        # Check for repeated XOR operations
        for i in range(len(content) - 4):
            if content[i:i+2] == b'\x33\xc0':  # xor eax, eax
                patterns.append({
                    'offset': i,
                    'pattern': 'xor_eax_eax',
                    'bytes': content[i:i+2].hex()
                })
        
        return patterns
    
    def _find_string_obfuscation(self, content: bytes) -> List[Dict[str, Any]]:
        """Find string obfuscation patterns"""
        patterns = []
        
        # Look for encrypted strings
        # This is a simplified example - in practice, you'd use more sophisticated analysis
        
        # Check for high-entropy regions that might be encrypted strings
        chunk_size = 32
        for i in range(0, len(content) - chunk_size, chunk_size):
            chunk = content[i:i+chunk_size]
            entropy = self._calculate_entropy(chunk)
            
            if entropy > 7.0:  # High entropy might indicate encryption
                patterns.append({
                    'offset': i,
                    'entropy': entropy,
                    'chunk_size': chunk_size,
                    'bytes': chunk.hex()
                })
        
        return patterns
    
    def _attempt_pattern_deobfuscation(self, content: bytes, pattern: Dict[str, Any]) -> Dict[str, Any]:
        """Attempt to deobfuscate a specific pattern"""
        result = {
            'pattern_type': pattern['type'],
            'success': False,
            'deobfuscated_data': None,
            'method_used': None
        }
        
        try:
            if pattern['type'] == 'xor_obfuscation':
                # Attempt XOR deobfuscation
                result['method_used'] = 'xor_decryption'
                result['success'] = self._attempt_xor_deobfuscation(content, pattern)
            
            elif pattern['type'] == 'string_obfuscation':
                # Attempt string deobfuscation
                result['method_used'] = 'string_decryption'
                result['success'] = self._attempt_string_deobfuscation(content, pattern)
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _attempt_xor_deobfuscation(self, content: bytes, pattern: Dict[str, Any]) -> bool:
        """Attempt XOR deobfuscation"""
        try:
            # This is a simplified example - in practice, you'd use more sophisticated analysis
            # to identify the XOR key and apply it
            
            # For now, just return False to indicate no successful deobfuscation
            return False
            
        except Exception as e:
            return False
    
    def _attempt_string_deobfuscation(self, content: bytes, pattern: Dict[str, Any]) -> bool:
        """Attempt string deobfuscation"""
        try:
            # This is a simplified example - in practice, you'd use more sophisticated analysis
            # to identify the decryption method and apply it
            
            # For now, just return False to indicate no successful deobfuscation
            return False
            
        except Exception as e:
            return False
    
    def _deobfuscate_strings(self, target_path: str) -> Dict[str, Any]:
        """Deobfuscate strings in the target"""
        try:
            results = {
                'strings_found': [],
                'deobfuscated_strings': [],
                'deobfuscation_methods': []
            }
            
            # Read file content
            with open(target_path, 'rb') as f:
                content = f.read()
            
            # Extract strings
            strings = self._extract_strings(content)
            results['strings_found'] = strings
            
            # Attempt to deobfuscate each string
            for string in strings:
                deobfuscated = self._deobfuscate_string(string)
                if deobfuscated:
                    results['deobfuscated_strings'].append(deobfuscated)
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _extract_strings(self, content: bytes) -> List[Dict[str, Any]]:
        """Extract strings from binary content"""
        strings = []
        
        # Simple string extraction - look for printable sequences
        current_string = b''
        start_offset = 0
        
        for i, byte in enumerate(content):
            if 32 <= byte <= 126:  # Printable ASCII
                if not current_string:
                    start_offset = i
                current_string += bytes([byte])
            else:
                if len(current_string) >= 4:  # Minimum string length
                    strings.append({
                        'offset': start_offset,
                        'length': len(current_string),
                        'content': current_string.decode('utf-8', errors='ignore')
                    })
                current_string = b''
        
        return strings
    
    def _deobfuscate_string(self, string_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Deobfuscate a single string"""
        try:
            content = string_info['content']
            
            # Try different deobfuscation methods
            methods = [
                self._try_xor_deobfuscation,
                self._try_base64_deobfuscation,
                self._try_rot13_deobfuscation
            ]
            
            for method in methods:
                result = method(content)
                if result:
                    return {
                        'original': content,
                        'deobfuscated': result,
                        'method': method.__name__
                    }
            
            return None
            
        except Exception as e:
            return None
    
    def _try_xor_deobfuscation(self, content: str) -> Optional[str]:
        """Try XOR deobfuscation"""
        try:
            # Try common XOR keys
            for key in range(1, 256):
                result = ''
                for char in content:
                    result += chr(ord(char) ^ key)
                
                # Check if result looks like readable text
                if self._is_readable_text(result):
                    return result
            
            return None
            
        except Exception as e:
            return None
    
    def _try_base64_deobfuscation(self, content: str) -> Optional[str]:
        """Try Base64 deobfuscation"""
        try:
            import base64
            
            # Try to decode as Base64
            decoded = base64.b64decode(content)
            result = decoded.decode('utf-8', errors='ignore')
            
            if self._is_readable_text(result):
                return result
            
            return None
            
        except Exception as e:
            return None
    
    def _try_rot13_deobfuscation(self, content: str) -> Optional[str]:
        """Try ROT13 deobfuscation"""
        try:
            result = ''
            for char in content:
                if 'a' <= char <= 'z':
                    result += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
                elif 'A' <= char <= 'Z':
                    result += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
                else:
                    result += char
            
            if self._is_readable_text(result):
                return result
            
            return None
            
        except Exception as e:
            return None
    
    def _is_readable_text(self, text: str) -> bool:
        """Check if text appears to be readable"""
        if not text:
            return False
        
        # Check if text contains mostly printable characters
        printable_count = sum(1 for c in text if c.isprintable())
        return printable_count / len(text) > 0.8
    
    def _deobfuscate_control_flow(self, target_path: str) -> Dict[str, Any]:
        """Deobfuscate control flow"""
        try:
            results = {
                'control_flow_patterns': [],
                'deobfuscation_attempts': [],
                'successful_deobfuscations': []
            }
            
            # This would typically involve analyzing control flow graphs
            # and identifying obfuscated control flow patterns
            
            results['note'] = 'Control flow deobfuscation requires advanced analysis'
            results['suggested_tools'] = ['IDA Pro', 'Ghidra', 'Radare2']
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _detect_anti_analysis(self, target_path: str) -> Dict[str, Any]:
        """Detect anti-analysis techniques"""
        try:
            results = {
                'anti_analysis_detected': False,
                'techniques': [],
                'indicators': []
            }
            
            # Read file content
            with open(target_path, 'rb') as f:
                content = f.read()
            
            content_str = content.decode('utf-8', errors='ignore')
            
            # Check for anti-debugging techniques
            anti_debug_patterns = [
                'IsDebuggerPresent',
                'CheckRemoteDebuggerPresent',
                'OutputDebugString',
                'GetTickCount',
                'QueryPerformanceCounter'
            ]
            
            for pattern in anti_debug_patterns:
                if pattern in content_str:
                    results['anti_analysis_detected'] = True
                    results['techniques'].append('anti_debugging')
                    results['indicators'].append(pattern)
            
            # Check for anti-VM techniques
            anti_vm_patterns = [
                'VMware',
                'VirtualBox',
                'QEMU',
                'Xen',
                'Hyper-V'
            ]
            
            for pattern in anti_vm_patterns:
                if pattern in content_str:
                    results['anti_analysis_detected'] = True
                    results['techniques'].append('anti_vm')
                    results['indicators'].append(pattern)
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
