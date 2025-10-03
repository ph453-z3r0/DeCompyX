#!/usr/bin/env python3
"""
Configuration Manager
NTRO Approved - Government of India Project

This module manages configuration for the reverse engineering automation tool
"""

import json
import os
import logging
from typing import Dict, Any, Optional, List
from pathlib import Path

class ConfigManager:
    """
    Configuration manager for reverse engineering automation tool
    """
    
    def __init__(self, config_file: str = "config.json"):
        self.config_file = config_file
        self.config = {}
        self.logger = logging.getLogger('ConfigManager')
        
        # Load configuration
        self._load_config()
    
    def _load_config(self):
        """Load configuration from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
                self.logger.info(f"Configuration loaded from {self.config_file}")
            else:
                self._create_default_config()
                self.logger.info(f"Default configuration created at {self.config_file}")
        except Exception as e:
            self.logger.error(f"Error loading configuration: {str(e)}")
            self._create_default_config()
    
    def _create_default_config(self):
        """Create default configuration"""
        self.config = {
            "project_info": {
                "name": "Reverse Engineering Automation Tool",
                "version": "1.0.0",
                "organization": "NTRO - Government of India",
                "description": "Automated reverse engineering tool for security analysis"
            },
            "tools": {
                "ghidra": {
                    "enabled": True,
                    "path": "ghidra",
                    "headless": True,
                    "timeout": 300
                },
                "radare2": {
                    "enabled": True,
                    "path": "r2",
                    "timeout": 60
                },
                "capstone": {
                    "enabled": True,
                    "timeout": 30
                },
                "x64dbg": {
                    "enabled": False,
                    "path": "x64dbg.exe",
                    "timeout": 300
                },
                "qemu": {
                    "enabled": False,
                    "path": "qemu-system-x86_64",
                    "timeout": 600
                },
                "frida": {
                    "enabled": True,
                    "timeout": 60
                },
                "angr": {
                    "enabled": True,
                    "timeout": 600,
                    "max_paths": 1000
                },
                "klee": {
                    "enabled": False,
                    "path": "klee",
                    "timeout": 1200
                },
                "loki": {
                    "enabled": False,
                    "path": "loki.py",
                    "timeout": 300
                },
                "dfsan": {
                    "enabled": False,
                    "timeout": 300
                },
                "strings": {
                    "enabled": True,
                    "path": "strings",
                    "min_length": 4
                },
                "binwalk": {
                    "enabled": True,
                    "path": "binwalk",
                    "timeout": 300
                }
            },
            "static_analysis": {
                "enabled": True,
                "timeout": 300,
                "max_file_size": 100 * 1024 * 1024,  # 100MB
                "extract_strings": True,
                "analyze_imports": True,
                "calculate_entropy": True
            },
            "dynamic_analysis": {
                "enabled": True,
                "timeout": 300,
                "sandbox_dir": "sandbox",
                "monitor_processes": True,
                "monitor_network": True,
                "monitor_filesystem": True,
                "monitor_registry": True
            },
            "symbolic_execution": {
                "enabled": True,
                "timeout": 600,
                "max_paths": 1000,
                "results_dir": "symbolic_results",
                "vulnerability_detection": True,
                "constraint_solving": True
            },
            "deobfuscation": {
                "enabled": True,
                "timeout": 300,
                "results_dir": "deobfuscation_results",
                "pattern_detection": True,
                "string_deobfuscation": True,
                "control_flow_deobfuscation": True,
                "anti_analysis_detection": True
            },
            "string_mining": {
                "enabled": True,
                "timeout": 300,
                "results_dir": "string_mining_results",
                "min_string_length": 4,
                "max_strings": 10000,
                "extract_urls": True,
                "extract_paths": True,
                "extract_apis": True,
                "detect_crypto": True
            },
            "output": {
                "results_dir": "results",
                "reports_dir": "reports",
                "logs_dir": "logs",
                "temp_dir": "temp",
                "format": "json",
                "include_screenshots": False,
                "include_artifacts": True
            },
            "security": {
                "sandbox_mode": True,
                "isolate_network": True,
                "quarantine_results": True,
                "encrypt_output": False,
                "hash_verification": True
            },
            "logging": {
                "level": "INFO",
                "file_logging": True,
                "console_logging": True,
                "max_file_size": 10 * 1024 * 1024,  # 10MB
                "backup_count": 5
            }
        }
        
        # Save default configuration
        self.save_config()
    
    def save_config(self):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            self.logger.info(f"Configuration saved to {self.config_file}")
        except Exception as e:
            self.logger.error(f"Error saving configuration: {str(e)}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key (supports dot notation)"""
        try:
            keys = key.split('.')
            value = self.config
            
            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    return default
            
            return value
        except Exception as e:
            self.logger.error(f"Error getting configuration value for key '{key}': {str(e)}")
            return default
    
    def set(self, key: str, value: Any):
        """Set configuration value by key (supports dot notation)"""
        try:
            keys = key.split('.')
            config = self.config
            
            # Navigate to the parent of the target key
            for k in keys[:-1]:
                if k not in config:
                    config[k] = {}
                config = config[k]
            
            # Set the value
            config[keys[-1]] = value
            
            self.logger.info(f"Configuration value set: {key} = {value}")
        except Exception as e:
            self.logger.error(f"Error setting configuration value for key '{key}': {str(e)}")
    
    def update(self, updates: Dict[str, Any]):
        """Update multiple configuration values"""
        try:
            for key, value in updates.items():
                self.set(key, value)
            self.logger.info(f"Configuration updated with {len(updates)} values")
        except Exception as e:
            self.logger.error(f"Error updating configuration: {str(e)}")
    
    def get_tool_config(self, tool_name: str) -> Dict[str, Any]:
        """Get configuration for a specific tool"""
        return self.get(f'tools.{tool_name}', {})
    
    def is_tool_enabled(self, tool_name: str) -> bool:
        """Check if a tool is enabled"""
        return self.get(f'tools.{tool_name}.enabled', False)
    
    def get_tool_path(self, tool_name: str) -> Optional[str]:
        """Get path for a specific tool"""
        return self.get(f'tools.{tool_name}.path')
    
    def get_tool_timeout(self, tool_name: str) -> int:
        """Get timeout for a specific tool"""
        return self.get(f'tools.{tool_name}.timeout', 300)
    
    def get_analysis_config(self, analysis_type: str) -> Dict[str, Any]:
        """Get configuration for a specific analysis type"""
        return self.get(analysis_type, {})
    
    def is_analysis_enabled(self, analysis_type: str) -> bool:
        """Check if an analysis type is enabled"""
        return self.get(f'{analysis_type}.enabled', False)
    
    def get_output_config(self) -> Dict[str, Any]:
        """Get output configuration"""
        return self.get('output', {})
    
    def get_security_config(self) -> Dict[str, Any]:
        """Get security configuration"""
        return self.get('security', {})
    
    def get_logging_config(self) -> Dict[str, Any]:
        """Get logging configuration"""
        return self.get('logging', {})
    
    def validate_config(self) -> List[str]:
        """Validate configuration and return list of issues"""
        issues = []
        
        try:
            # Check required directories
            output_dir = self.get('output.results_dir', 'results')
            if not os.path.exists(output_dir):
                try:
                    os.makedirs(output_dir, exist_ok=True)
                except Exception as e:
                    issues.append(f"Cannot create output directory '{output_dir}': {str(e)}")
            
            # Check tool paths
            tools = self.get('tools', {})
            for tool_name, tool_config in tools.items():
                if tool_config.get('enabled', False):
                    tool_path = tool_config.get('path')
                    if tool_path and not self._check_tool_availability(tool_path):
                        issues.append(f"Tool '{tool_name}' not found at path '{tool_path}'")
            
            # Check analysis configurations
            analysis_types = ['static_analysis', 'dynamic_analysis', 'symbolic_execution', 
                            'deobfuscation', 'string_mining']
            
            for analysis_type in analysis_types:
                config = self.get(analysis_type, {})
                timeout = config.get('timeout', 300)
                if timeout <= 0:
                    issues.append(f"Invalid timeout for {analysis_type}: {timeout}")
            
        except Exception as e:
            issues.append(f"Configuration validation error: {str(e)}")
        
        return issues
    
    def _check_tool_availability(self, tool_path: str) -> bool:
        """Check if a tool is available"""
        try:
            import subprocess
            result = subprocess.run([tool_path, '--version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except:
            return False
    
    def export_config(self, export_path: str):
        """Export configuration to a file"""
        try:
            with open(export_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            self.logger.info(f"Configuration exported to {export_path}")
        except Exception as e:
            self.logger.error(f"Error exporting configuration: {str(e)}")
    
    def import_config(self, import_path: str):
        """Import configuration from a file"""
        try:
            with open(import_path, 'r') as f:
                imported_config = json.load(f)
            
            # Merge with existing configuration
            self.config.update(imported_config)
            self.save_config()
            self.logger.info(f"Configuration imported from {import_path}")
        except Exception as e:
            self.logger.error(f"Error importing configuration: {str(e)}")
    
    def reset_to_default(self):
        """Reset configuration to default values"""
        try:
            self._create_default_config()
            self.logger.info("Configuration reset to default values")
        except Exception as e:
            self.logger.error(f"Error resetting configuration: {str(e)}")
    
    def get_project_info(self) -> Dict[str, Any]:
        """Get project information"""
        return self.get('project_info', {})
    
    def get_version(self) -> str:
        """Get tool version"""
        return self.get('project_info.version', '1.0.0')
    
    def get_organization(self) -> str:
        """Get organization name"""
        return self.get('project_info.organization', 'NTRO - Government of India')
