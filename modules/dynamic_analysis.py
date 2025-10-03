#!/usr/bin/env python3
"""
Dynamic Analysis Module
NTRO Approved - Government of India Project

This module provides dynamic analysis capabilities using:
- x64dbg: Debugger for Windows executables
- QEMU: Emulator to run programs on different architectures
- Frida: Injecting scripts into running processes
"""

import os
import json
import subprocess
import logging
import time
import threading
from pathlib import Path
from typing import Dict, List, Any, Optional
import tempfile
import psutil

class DynamicAnalyzer:
    """
    Dynamic analysis engine using x64dbg, QEMU, and Frida
    """
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger('DynamicAnalyzer')
        
        # Tool paths from config
        self.x64dbg_path = config.get('tools', {}).get('x64dbg', {}).get('path', 'x64dbg.exe')
        self.qemu_path = config.get('tools', {}).get('qemu', {}).get('path', 'qemu-system-x86_64')
        self.frida_available = config.get('tools', {}).get('frida', {}).get('enabled', True)
        
        # Analysis options
        self.analysis_options = config.get('dynamic_analysis', {})
        self.timeout = self.analysis_options.get('timeout', 300)  # 5 minutes default
        
        # Sandbox environment
        self.sandbox_dir = self.analysis_options.get('sandbox_dir', 'sandbox')
        os.makedirs(self.sandbox_dir, exist_ok=True)
    
    def analyze(self, target_path: str) -> Dict[str, Any]:
        """
        Perform comprehensive dynamic analysis on target
        
        Args:
            target_path: Path to the target binary
        
        Returns:
            Dictionary containing dynamic analysis results
        """
        self.logger.info(f"Starting dynamic analysis of: {target_path}")
        
        results = {
            'target': target_path,
            'analysis_type': 'dynamic',
            'tools_used': [],
            'results': {}
        }
        
        try:
            # Pre-execution analysis
            results['results']['pre_execution'] = self._pre_execution_analysis(target_path)
            
            # Frida analysis (if available)
            if self.frida_available:
                results['results']['frida'] = self._frida_analysis(target_path)
                results['tools_used'].append('frida')
            
            # QEMU analysis (if available)
            if self._check_tool_availability('qemu'):
                results['results']['qemu'] = self._qemu_analysis(target_path)
                results['tools_used'].append('qemu')
            
            # Process monitoring
            results['results']['process_monitoring'] = self._monitor_process_execution(target_path)
            
            # Network analysis
            results['results']['network_analysis'] = self._analyze_network_behavior(target_path)
            
            # File system monitoring
            results['results']['filesystem_monitoring'] = self._monitor_filesystem_changes(target_path)
            
            # Memory analysis
            results['results']['memory_analysis'] = self._analyze_memory_behavior(target_path)
            
            # Registry analysis (Windows)
            if os.name == 'nt':
                results['results']['registry_analysis'] = self._analyze_registry_changes(target_path)
            
        except Exception as e:
            self.logger.error(f"Error in dynamic analysis: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def _check_tool_availability(self, tool_name: str) -> bool:
        """Check if a tool is available in the system"""
        try:
            if tool_name == 'qemu':
                result = subprocess.run([self.qemu_path, '--version'], 
                                      capture_output=True, text=True, timeout=10)
                return result.returncode == 0
            elif tool_name == 'x64dbg':
                return os.path.exists(self.x64dbg_path)
            return False
        except:
            return False
    
    def _pre_execution_analysis(self, target_path: str) -> Dict[str, Any]:
        """Analyze target before execution"""
        try:
            results = {}
            
            # Check if file is executable
            results['is_executable'] = os.access(target_path, os.X_OK)
            
            # Check dependencies
            results['dependencies'] = self._check_dependencies(target_path)
            
            # Check for suspicious characteristics
            results['suspicious_indicators'] = self._check_suspicious_indicators(target_path)
            
            # File permissions
            stat = os.stat(target_path)
            results['permissions'] = oct(stat.st_mode)
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _check_dependencies(self, target_path: str) -> Dict[str, Any]:
        """Check binary dependencies"""
        try:
            dependencies = []
            
            # Try using ldd (Linux) or objdump
            try:
                if os.name != 'nt':
                    cmd = ['ldd', target_path]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        for line in lines:
                            if '=>' in line:
                                parts = line.split('=>')
                                if len(parts) >= 2:
                                    lib_name = parts[0].strip()
                                    lib_path = parts[1].split()[0].strip()
                                    dependencies.append({
                                        'name': lib_name,
                                        'path': lib_path
                                    })
            except:
                pass
            
            return {'dependencies': dependencies}
            
        except Exception as e:
            return {'error': str(e)}
    
    def _check_suspicious_indicators(self, target_path: str) -> Dict[str, Any]:
        """Check for suspicious indicators"""
        try:
            indicators = []
            
            # Check file size (very small or very large)
            file_size = os.path.getsize(target_path)
            if file_size < 1024:  # Less than 1KB
                indicators.append('Very small file size')
            elif file_size > 100 * 1024 * 1024:  # More than 100MB
                indicators.append('Very large file size')
            
            # Check for common malware extensions
            suspicious_extensions = ['.scr', '.pif', '.bat', '.cmd', '.com']
            if Path(target_path).suffix.lower() in suspicious_extensions:
                indicators.append('Suspicious file extension')
            
            # Check entropy (high entropy might indicate packing/encryption)
            try:
                with open(target_path, 'rb') as f:
                    data = f.read(1024)  # Read first 1KB
                
                if data:
                    import math
                    byte_counts = [0] * 256
                    for byte in data:
                        byte_counts[byte] += 1
                    
                    entropy = 0
                    for count in byte_counts:
                        if count > 0:
                            probability = count / len(data)
                            entropy -= probability * math.log2(probability)
                    
                    if entropy > 7.5:
                        indicators.append('High entropy (possibly packed/encrypted)')
            except:
                pass
            
            return {
                'indicators': indicators,
                'risk_level': 'high' if len(indicators) > 2 else 'medium' if indicators else 'low'
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _frida_analysis(self, target_path: str) -> Dict[str, Any]:
        """Perform analysis using Frida"""
        try:
            results = {}
            
            # Create Frida script for analysis
            frida_script = '''
// Frida script for dynamic analysis
console.log("Starting Frida analysis...");

// Hook common API calls
var apiHooks = [
    'kernel32.dll!CreateFileA',
    'kernel32.dll!CreateFileW',
    'kernel32.dll!WriteFile',
    'kernel32.dll!ReadFile',
    'kernel32.dll!DeleteFileA',
    'kernel32.dll!DeleteFileW',
    'ws2_32.dll!socket',
    'ws2_32.dll!connect',
    'ws2_32.dll!send',
    'ws2_32.dll!recv',
    'advapi32.dll!RegOpenKeyExA',
    'advapi32.dll!RegSetValueExA',
    'advapi32.dll!RegDeleteValueA'
];

var hooks = [];

apiHooks.forEach(function(api) {
    try {
        var parts = api.split('!');
        var module = parts[0];
        var function = parts[1];
        
        var moduleBase = Module.findBaseAddress(module);
        if (moduleBase) {
            var funcAddr = Module.findExportByName(module, function);
            if (funcAddr) {
                var hook = Interceptor.attach(funcAddr, {
                    onEnter: function(args) {
                        console.log("[HOOK] " + api + " called");
                        console.log("  Args: " + args.map(function(arg) {
                            return arg.toString();
                        }).join(', '));
                    },
                    onLeave: function(retval) {
                        console.log("[HOOK] " + api + " returned: " + retval.toString());
                    }
                });
                hooks.push(hook);
            }
        }
    } catch (e) {
        console.log("Failed to hook " + api + ": " + e.message);
    }
});

// Monitor process creation
Process.enumerateThreads().forEach(function(thread) {
    console.log("Thread ID: " + thread.id);
});

console.log("Frida hooks installed. Monitoring for " + (30 * 1000) + "ms...");

// Run for 30 seconds
setTimeout(function() {
    console.log("Analysis complete.");
    hooks.forEach(function(hook) {
        hook.detach();
    });
}, 30000);
'''
            
            # Write script to temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
                f.write(frida_script)
                script_path = f.name
            
            try:
                # Run Frida analysis
                cmd = ['frida', '-f', target_path, '-l', script_path, '--runtime=v8']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if result.returncode == 0:
                    results['output'] = result.stdout
                    results['hooks_installed'] = len(apiHooks)
                else:
                    results['error'] = result.stderr
                
            finally:
                # Clean up script file
                try:
                    os.unlink(script_path)
                except:
                    pass
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _qemu_analysis(self, target_path: str) -> Dict[str, Any]:
        """Perform analysis using QEMU emulation"""
        try:
            results = {}
            
            # Create a minimal Linux environment for analysis
            # This is a simplified example - in practice, you'd need a proper VM image
            
            # Check if target is a Linux binary
            with open(target_path, 'rb') as f:
                header = f.read(4)
            
            if header != b'\x7fELF':
                return {'note': 'QEMU analysis requires ELF binary', 'skipped': True}
            
            # For demonstration, we'll just check if QEMU can load the binary
            # In a real implementation, you'd set up a proper VM environment
            
            results['note'] = 'QEMU analysis requires proper VM setup'
            results['suggestion'] = 'Set up Linux VM image for full QEMU analysis'
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _monitor_process_execution(self, target_path: str) -> Dict[str, Any]:
        """Monitor process execution"""
        try:
            results = {
                'process_info': {},
                'execution_log': [],
                'errors': []
            }
            
            # Start process monitoring
            start_time = time.time()
            
            try:
                # Execute the target with timeout
                process = subprocess.Popen(
                    [target_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    cwd=self.sandbox_dir
                )
                
                # Monitor process
                process_info = {
                    'pid': process.pid,
                    'start_time': start_time,
                    'status': 'running'
                }
                
                # Wait for process to complete or timeout
                try:
                    stdout, stderr = process.communicate(timeout=self.timeout)
                    process_info['status'] = 'completed'
                    process_info['return_code'] = process.returncode
                    process_info['stdout'] = stdout.decode('utf-8', errors='ignore')[:1000]  # Limit output
                    process_info['stderr'] = stderr.decode('utf-8', errors='ignore')[:1000]
                except subprocess.TimeoutExpired:
                    process.kill()
                    process_info['status'] = 'timeout'
                    process_info['return_code'] = -1
                
                results['process_info'] = process_info
                
            except Exception as e:
                results['errors'].append(f'Process execution failed: {str(e)}')
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_network_behavior(self, target_path: str) -> Dict[str, Any]:
        """Analyze network behavior"""
        try:
            results = {
                'network_connections': [],
                'dns_queries': [],
                'http_requests': []
            }
            
            # This would typically involve network monitoring tools
            # For now, we'll provide a framework
            
            results['note'] = 'Network analysis requires additional monitoring tools'
            results['suggested_tools'] = ['Wireshark', 'tcpdump', 'netstat']
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _monitor_filesystem_changes(self, target_path: str) -> Dict[str, Any]:
        """Monitor filesystem changes"""
        try:
            results = {
                'files_created': [],
                'files_modified': [],
                'files_deleted': [],
                'directories_created': []
            }
            
            # Get initial filesystem state
            initial_files = set()
            for root, dirs, files in os.walk(self.sandbox_dir):
                for file in files:
                    initial_files.add(os.path.join(root, file))
            
            # Execute target (simplified)
            try:
                process = subprocess.Popen(
                    [target_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    cwd=self.sandbox_dir
                )
                
                # Wait briefly for filesystem changes
                time.sleep(2)
                
                # Get final filesystem state
                final_files = set()
                for root, dirs, files in os.walk(self.sandbox_dir):
                    for file in files:
                        final_files.add(os.path.join(root, file))
                
                # Determine changes
                created_files = final_files - initial_files
                deleted_files = initial_files - final_files
                
                results['files_created'] = list(created_files)
                results['files_deleted'] = list(deleted_files)
                
                # Terminate process
                process.terminate()
                process.wait(timeout=5)
                
            except Exception as e:
                results['error'] = str(e)
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_memory_behavior(self, target_path: str) -> Dict[str, Any]:
        """Analyze memory behavior"""
        try:
            results = {
                'memory_usage': {},
                'memory_patterns': [],
                'heap_analysis': {}
            }
            
            # This would typically involve memory analysis tools
            # For now, we'll provide a framework
            
            results['note'] = 'Memory analysis requires additional tools'
            results['suggested_tools'] = ['Volatility', 'WinDbg', 'GDB']
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_registry_changes(self, target_path: str) -> Dict[str, Any]:
        """Analyze registry changes (Windows only)"""
        try:
            results = {
                'registry_keys_modified': [],
                'registry_values_created': [],
                'registry_values_deleted': []
            }
            
            if os.name != 'nt':
                return {'note': 'Registry analysis only available on Windows'}
            
            # This would typically involve registry monitoring
            # For now, we'll provide a framework
            
            results['note'] = 'Registry analysis requires additional monitoring tools'
            results['suggested_tools'] = ['Process Monitor', 'RegShot']
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
