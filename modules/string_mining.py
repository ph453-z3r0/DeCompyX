#!/usr/bin/env python3
"""
String and Data Mining Module
NTRO Approved - Government of India Project

This module provides string and data mining capabilities using:
- strings (Sysinternals): Extracts printable strings from binaries
- Binwalk: For analyzing binary firmware and extracting embedded files
- Custom string analysis algorithms
"""

import os
import json
import subprocess
import logging
import re
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional
import hashlib
import base64
import binascii

class StringMiner:
    """
    String and data mining engine using strings, Binwalk, and custom algorithms
    """
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger('StringMiner')
        
        # Tool paths from config
        self.strings_path = config.get('tools', {}).get('strings', {}).get('path', 'strings')
        self.binwalk_path = config.get('tools', {}).get('binwalk', {}).get('path', 'binwalk')
        
        # Analysis options
        self.analysis_options = config.get('string_mining', {})
        self.min_string_length = self.analysis_options.get('min_string_length', 4)
        self.max_strings = self.analysis_options.get('max_strings', 10000)
        
        # Results directory
        self.results_dir = self.analysis_options.get('results_dir', 'string_mining_results')
        os.makedirs(self.results_dir, exist_ok=True)
        
        # String patterns for analysis
        self.string_patterns = self._load_string_patterns()
    
    def analyze(self, target_path: str) -> Dict[str, Any]:
        """
        Perform comprehensive string and data mining analysis on target
        
        Args:
            target_path: Path to the target binary
        
        Returns:
            Dictionary containing string mining results
        """
        self.logger.info(f"Starting string mining analysis of: {target_path}")
        
        results = {
            'target': target_path,
            'analysis_type': 'string_mining',
            'tools_used': [],
            'results': {}
        }
        
        try:
            # Basic string extraction
            results['results']['basic_strings'] = self.extract_strings(target_path)
            
            # Advanced string analysis
            results['results']['advanced_strings'] = self._analyze_strings(target_path)
            
            # Binwalk analysis (if available)
            if self._check_tool_availability('binwalk'):
                results['results']['binwalk'] = self._binwalk_analysis(target_path)
                results['tools_used'].append('binwalk')
            
            # Pattern-based string analysis
            results['results']['pattern_analysis'] = self._pattern_based_analysis(target_path)
            
            # Encoded string detection
            results['results']['encoded_strings'] = self._detect_encoded_strings(target_path)
            
            # URL and path extraction
            results['results']['urls_paths'] = self._extract_urls_and_paths(target_path)
            
            # API and function name extraction
            results['results']['apis_functions'] = self._extract_apis_and_functions(target_path)
            
            # Configuration data extraction
            results['results']['config_data'] = self._extract_config_data(target_path)
            
            # Cryptographic material detection
            results['results']['crypto_material'] = self._detect_crypto_material(target_path)
            
        except Exception as e:
            self.logger.error(f"Error in string mining analysis: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def extract_strings(self, target_path: str, max_length: int = 1000) -> Dict[str, Any]:
        """
        Extract basic strings from target
        
        Args:
            target_path: Path to the target binary
            max_length: Maximum number of strings to extract
        
        Returns:
            Dictionary containing extracted strings
        """
        try:
            results = {
                'strings': [],
                'count': 0,
                'method': 'basic_extraction'
            }
            
            # Method 1: Using strings command
            strings_result = self._extract_with_strings_command(target_path)
            if strings_result:
                results['strings'].extend(strings_result[:max_length])
                results['method'] = 'strings_command'
            
            # Method 2: Custom extraction
            custom_result = self._extract_with_custom_method(target_path)
            if custom_result:
                results['strings'].extend(custom_result[:max_length])
                if results['method'] == 'basic_extraction':
                    results['method'] = 'custom_extraction'
                else:
                    results['method'] = 'hybrid_extraction'
            
            # Remove duplicates and sort
            results['strings'] = list(set(results['strings']))
            results['strings'].sort()
            results['count'] = len(results['strings'])
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _check_tool_availability(self, tool_name: str) -> bool:
        """Check if a tool is available in the system"""
        try:
            if tool_name == 'strings':
                result = subprocess.run([self.strings_path, '--version'], 
                                      capture_output=True, text=True, timeout=10)
                return result.returncode == 0
            elif tool_name == 'binwalk':
                result = subprocess.run([self.binwalk_path, '--version'], 
                                      capture_output=True, text=True, timeout=10)
                return result.returncode == 0
            return False
        except:
            return False
    
    def _load_string_patterns(self) -> Dict[str, List[str]]:
        """Load string patterns for analysis"""
        return {
            'urls': [
                r'https?://[^\s<>"{}|\\^`\[\]]+',
                r'ftp://[^\s<>"{}|\\^`\[\]]+',
                r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>"{}|\\^`\[\]]*)?'
            ],
            'email_addresses': [
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            ],
            'ip_addresses': [
                r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
            ],
            'file_paths': [
                r'[a-zA-Z]:\\[^<>:"/\\|?*\x00-\x1f]*',
                r'/[^<>:"/\\|?*\x00-\x1f]*',
                r'\./[^<>:"/\\|?*\x00-\x1f]*'
            ],
            'registry_keys': [
                r'HKEY_[A-Z_]+\\[^<>:"/\\|?*\x00-\x1f]*'
            ],
            'api_calls': [
                r'[A-Z][a-zA-Z]*[A-Z][a-zA-Z]*',
                r'[a-zA-Z_][a-zA-Z0-9_]*\([^)]*\)'
            ],
            'base64': [
                r'[A-Za-z0-9+/]{4,}={0,2}'
            ],
            'hex_strings': [
                r'[0-9a-fA-F]{8,}'
            ],
            'crypto_indicators': [
                r'AES|DES|RSA|MD5|SHA1|SHA256|SHA512',
                r'encrypt|decrypt|cipher|hash|signature'
            ]
        }
    
    def _extract_with_strings_command(self, target_path: str) -> List[str]:
        """Extract strings using the strings command"""
        try:
            cmd = [self.strings_path, '-a', '-n', str(self.min_string_length), target_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                strings = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                return strings[:self.max_strings]
            
            return []
            
        except Exception as e:
            self.logger.warning(f"Strings command failed: {str(e)}")
            return []
    
    def _extract_with_custom_method(self, target_path: str) -> List[str]:
        """Extract strings using custom method"""
        try:
            strings = []
            
            with open(target_path, 'rb') as f:
                content = f.read()
            
            # Extract ASCII strings
            ascii_strings = self._extract_ascii_strings(content)
            strings.extend(ascii_strings)
            
            # Extract Unicode strings
            unicode_strings = self._extract_unicode_strings(content)
            strings.extend(unicode_strings)
            
            # Extract wide strings
            wide_strings = self._extract_wide_strings(content)
            strings.extend(wide_strings)
            
            return strings[:self.max_strings]
            
        except Exception as e:
            self.logger.warning(f"Custom string extraction failed: {str(e)}")
            return []
    
    def _extract_ascii_strings(self, content: bytes) -> List[str]:
        """Extract ASCII strings from binary content"""
        strings = []
        current_string = b''
        
        for byte in content:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += bytes([byte])
            else:
                if len(current_string) >= self.min_string_length:
                    strings.append(current_string.decode('utf-8', errors='ignore'))
                current_string = b''
        
        # Handle string at end of file
        if len(current_string) >= self.min_string_length:
            strings.append(current_string.decode('utf-8', errors='ignore'))
        
        return strings
    
    def _extract_unicode_strings(self, content: bytes) -> List[str]:
        """Extract Unicode strings from binary content"""
        strings = []
        
        # Look for UTF-8 strings
        try:
            text = content.decode('utf-8', errors='ignore')
            # Extract sequences of printable characters
            pattern = r'[^\x00-\x1f\x7f-\x9f]{' + str(self.min_string_length) + ',}'
            matches = re.findall(pattern, text)
            strings.extend(matches)
        except:
            pass
        
        return strings
    
    def _extract_wide_strings(self, content: bytes) -> List[str]:
        """Extract wide strings from binary content"""
        strings = []
        
        # Look for UTF-16 strings (little-endian)
        for i in range(0, len(content) - 1, 2):
            if i + 1 < len(content):
                char = content[i] | (content[i + 1] << 8)
                if 32 <= char <= 126:  # Printable ASCII in wide format
                    # Extract the wide string
                    wide_string = b''
                    j = i
                    while j + 1 < len(content):
                        char = content[j] | (content[j + 1] << 8)
                        if 32 <= char <= 126:
                            wide_string += bytes([char])
                            j += 2
                        else:
                            break
                    
                    if len(wide_string) >= self.min_string_length:
                        strings.append(wide_string.decode('utf-8', errors='ignore'))
        
        return strings
    
    def _analyze_strings(self, target_path: str) -> Dict[str, Any]:
        """Perform advanced string analysis"""
        try:
            results = {
                'string_categories': {},
                'suspicious_strings': [],
                'string_statistics': {}
            }
            
            # Extract all strings
            strings_result = self.extract_strings(target_path)
            if 'strings' not in strings_result:
                return {'error': 'Failed to extract strings'}
            
            strings = strings_result['strings']
            
            # Categorize strings
            results['string_categories'] = self._categorize_strings(strings)
            
            # Find suspicious strings
            results['suspicious_strings'] = self._find_suspicious_strings(strings)
            
            # Calculate statistics
            results['string_statistics'] = self._calculate_string_statistics(strings)
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _categorize_strings(self, strings: List[str]) -> Dict[str, List[str]]:
        """Categorize strings by type"""
        categories = {
            'urls': [],
            'email_addresses': [],
            'ip_addresses': [],
            'file_paths': [],
            'registry_keys': [],
            'api_calls': [],
            'base64': [],
            'hex_strings': [],
            'crypto_indicators': [],
            'other': []
        }
        
        for string in strings:
            categorized = False
            
            for category, patterns in self.string_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, string, re.IGNORECASE):
                        categories[category].append(string)
                        categorized = True
                        break
                if categorized:
                    break
            
            if not categorized:
                categories['other'].append(string)
        
        return categories
    
    def _find_suspicious_strings(self, strings: List[str]) -> List[Dict[str, Any]]:
        """Find suspicious strings"""
        suspicious_strings = []
        
        # Suspicious patterns
        suspicious_patterns = [
            (r'password|passwd|pwd', 'password_related'),
            (r'admin|root|administrator', 'admin_related'),
            (r'backdoor|trojan|virus|malware', 'malware_related'),
            (r'exploit|payload|shellcode', 'exploit_related'),
            (r'keylog|logger|spy', 'spyware_related'),
            (r'botnet|bot|zombie', 'botnet_related'),
            (r'ransom|encrypt|decrypt', 'ransomware_related'),
            (r'steal|theft|hack', 'theft_related'),
            (r'bypass|evade|hide', 'evasion_related'),
            (r'inject|hook|patch', 'injection_related')
        ]
        
        for string in strings:
            for pattern, category in suspicious_patterns:
                if re.search(pattern, string, re.IGNORECASE):
                    suspicious_strings.append({
                        'string': string,
                        'category': category,
                        'pattern': pattern
                    })
                    break
        
        return suspicious_strings
    
    def _calculate_string_statistics(self, strings: List[str]) -> Dict[str, Any]:
        """Calculate string statistics"""
        if not strings:
            return {}
        
        lengths = [len(s) for s in strings]
        
        return {
            'total_strings': len(strings),
            'average_length': sum(lengths) / len(lengths),
            'min_length': min(lengths),
            'max_length': max(lengths),
            'unique_strings': len(set(strings)),
            'duplicate_strings': len(strings) - len(set(strings))
        }
    
    def _binwalk_analysis(self, target_path: str) -> Dict[str, Any]:
        """Perform analysis using Binwalk"""
        try:
            results = {}
            
            # Run Binwalk analysis
            cmd = [self.binwalk_path, '-e', '-M', '-A', target_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                results['output'] = result.stdout
                results['status'] = 'completed'
                
                # Parse Binwalk output
                lines = result.stdout.split('\n')
                signatures = []
                
                for line in lines:
                    if 'DECIMAL' in line or 'HEXADECIMAL' in line:
                        continue
                    if line.strip() and not line.startswith(' '):
                        signatures.append(line.strip())
                
                results['signatures'] = signatures
            else:
                results['error'] = result.stderr
                results['status'] = 'failed'
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _pattern_based_analysis(self, target_path: str) -> Dict[str, Any]:
        """Perform pattern-based string analysis"""
        try:
            results = {
                'patterns_found': {},
                'pattern_matches': []
            }
            
            # Read file content
            with open(target_path, 'rb') as f:
                content = f.read()
            
            # Search for patterns
            for category, patterns in self.string_patterns.items():
                matches = []
                for pattern in patterns:
                    pattern_matches = re.findall(pattern, content.decode('utf-8', errors='ignore'), re.IGNORECASE)
                    matches.extend(pattern_matches)
                
                if matches:
                    results['patterns_found'][category] = list(set(matches))
                    results['pattern_matches'].extend([
                        {'category': category, 'match': match} for match in matches
                    ])
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _detect_encoded_strings(self, target_path: str) -> Dict[str, Any]:
        """Detect encoded strings"""
        try:
            results = {
                'base64_strings': [],
                'hex_strings': [],
                'encoded_patterns': []
            }
            
            # Read file content
            with open(target_path, 'rb') as f:
                content = f.read()
            
            content_str = content.decode('utf-8', errors='ignore')
            
            # Detect Base64 strings
            base64_pattern = r'[A-Za-z0-9+/]{4,}={0,2}'
            base64_matches = re.findall(base64_pattern, content_str)
            
            for match in base64_matches:
                try:
                    decoded = base64.b64decode(match)
                    if decoded.isascii():
                        results['base64_strings'].append({
                            'encoded': match,
                            'decoded': decoded.decode('utf-8', errors='ignore')
                        })
                except:
                    pass
            
            # Detect hex strings
            hex_pattern = r'[0-9a-fA-F]{8,}'
            hex_matches = re.findall(hex_pattern, content_str)
            
            for match in hex_matches:
                try:
                    decoded = bytes.fromhex(match)
                    if decoded.isascii():
                        results['hex_strings'].append({
                            'encoded': match,
                            'decoded': decoded.decode('utf-8', errors='ignore')
                        })
                except:
                    pass
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _extract_urls_and_paths(self, target_path: str) -> Dict[str, Any]:
        """Extract URLs and file paths"""
        try:
            results = {
                'urls': [],
                'file_paths': [],
                'registry_paths': []
            }
            
            # Extract strings
            strings_result = self.extract_strings(target_path)
            if 'strings' not in strings_result:
                return {'error': 'Failed to extract strings'}
            
            strings = strings_result['strings']
            
            # Extract URLs
            url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
            for string in strings:
                urls = re.findall(url_pattern, string)
                results['urls'].extend(urls)
            
            # Extract file paths
            path_patterns = [
                r'[a-zA-Z]:\\[^<>:"/\\|?*\x00-\x1f]*',
                r'/[^<>:"/\\|?*\x00-\x1f]*',
                r'\./[^<>:"/\\|?*\x00-\x1f]*'
            ]
            
            for string in strings:
                for pattern in path_patterns:
                    paths = re.findall(pattern, string)
                    results['file_paths'].extend(paths)
            
            # Extract registry paths
            registry_pattern = r'HKEY_[A-Z_]+\\[^<>:"/\\|?*\x00-\x1f]*'
            for string in strings:
                registry_paths = re.findall(registry_pattern, string)
                results['registry_paths'].extend(registry_paths)
            
            # Remove duplicates
            results['urls'] = list(set(results['urls']))
            results['file_paths'] = list(set(results['file_paths']))
            results['registry_paths'] = list(set(results['registry_paths']))
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _extract_apis_and_functions(self, target_path: str) -> Dict[str, Any]:
        """Extract API calls and function names"""
        try:
            results = {
                'api_calls': [],
                'function_names': [],
                'imported_functions': []
            }
            
            # Extract strings
            strings_result = self.extract_strings(target_path)
            if 'strings' not in strings_result:
                return {'error': 'Failed to extract strings'}
            
            strings = strings_result['strings']
            
            # Common API patterns
            api_patterns = [
                r'[A-Z][a-zA-Z]*[A-Z][a-zA-Z]*',  # PascalCase
                r'[a-zA-Z_][a-zA-Z0-9_]*\([^)]*\)',  # Function calls
                r'Create[A-Z][a-zA-Z]*',  # Create functions
                r'Get[A-Z][a-zA-Z]*',  # Get functions
                r'Set[A-Z][a-zA-Z]*',  # Set functions
                r'Delete[A-Z][a-zA-Z]*',  # Delete functions
                r'Find[A-Z][a-zA-Z]*',  # Find functions
                r'Open[A-Z][a-zA-Z]*',  # Open functions
                r'Close[A-Z][a-zA-Z]*',  # Close functions
                r'Read[A-Z][a-zA-Z]*',  # Read functions
                r'Write[A-Z][a-zA-Z]*'  # Write functions
            ]
            
            for string in strings:
                for pattern in api_patterns:
                    matches = re.findall(pattern, string)
                    results['api_calls'].extend(matches)
            
            # Remove duplicates and sort
            results['api_calls'] = sorted(list(set(results['api_calls'])))
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _extract_config_data(self, target_path: str) -> Dict[str, Any]:
        """Extract configuration data"""
        try:
            results = {
                'config_strings': [],
                'key_value_pairs': [],
                'json_data': [],
                'xml_data': []
            }
            
            # Extract strings
            strings_result = self.extract_strings(target_path)
            if 'strings' not in strings_result:
                return {'error': 'Failed to extract strings'}
            
            strings = strings_result['strings']
            
            # Look for configuration patterns
            config_patterns = [
                r'[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*[^\s]+',  # Key=value pairs
                r'"[^"]*"\s*:\s*"[^"]*"',  # JSON-like pairs
                r'<[^>]+>.*?</[^>]+>',  # XML-like tags
                r'\{[^}]*\}',  # JSON-like objects
                r'\[[^\]]*\]'  # JSON-like arrays
            ]
            
            for string in strings:
                for pattern in config_patterns:
                    matches = re.findall(pattern, string)
                    if matches:
                        results['config_strings'].extend(matches)
            
            # Remove duplicates
            results['config_strings'] = list(set(results['config_strings']))
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _detect_crypto_material(self, target_path: str) -> Dict[str, Any]:
        """Detect cryptographic material"""
        try:
            results = {
                'crypto_algorithms': [],
                'crypto_keys': [],
                'crypto_indicators': [],
                'certificates': []
            }
            
            # Extract strings
            strings_result = self.extract_strings(target_path)
            if 'strings' not in strings_result:
                return {'error': 'Failed to extract strings'}
            
            strings = strings_result['strings']
            
            # Crypto algorithm patterns
            crypto_patterns = [
                r'AES|DES|RSA|MD5|SHA1|SHA256|SHA512|HMAC|PBKDF2',
                r'encrypt|decrypt|cipher|hash|signature|digest',
                r'public_key|private_key|secret_key|session_key',
                r'certificate|cert|ca|ssl|tls|https'
            ]
            
            for string in strings:
                for pattern in crypto_patterns:
                    if re.search(pattern, string, re.IGNORECASE):
                        results['crypto_indicators'].append(string)
                        break
            
            # Look for potential keys (long hex strings)
            hex_pattern = r'[0-9a-fA-F]{32,}'
            for string in strings:
                hex_matches = re.findall(hex_pattern, string)
                for match in hex_matches:
                    if len(match) >= 32:  # Minimum key length
                        results['crypto_keys'].append(match)
            
            # Remove duplicates
            results['crypto_indicators'] = list(set(results['crypto_indicators']))
            results['crypto_keys'] = list(set(results['crypto_keys']))
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
