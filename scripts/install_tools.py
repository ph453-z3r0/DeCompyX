#!/usr/bin/env python3
"""
Tool Installation Script
NTRO Approved - Government of India Project

This script helps install and configure the required tools for reverse engineering automation
"""

import os
import sys
import subprocess
import platform
import json
import urllib.request
import zipfile
import tarfile
from pathlib import Path
import logging

class ToolInstaller:
    """
    Tool installer for reverse engineering automation
    """
    
    def __init__(self):
        self.system = platform.system().lower()
        self.arch = platform.machine().lower()
        self.logger = self._setup_logging()
        
        # Tool configurations
        self.tools_config = {
            'ghidra': {
                'name': 'Ghidra',
                'description': 'NSA Framework for binary analysis and decompilation',
                'url': 'https://github.com/NationalSecurityAgency/ghidra/releases/latest',
                'install_method': 'download',
                'required': True
            },
            'radare2': {
                'name': 'Radare2',
                'description': 'Disassembling, debugging, and patching framework',
                'url': 'https://github.com/radareorg/radare2',
                'install_method': 'git',
                'required': True
            },
            'capstone': {
                'name': 'Capstone',
                'description': 'Disassembly framework',
                'install_method': 'pip',
                'required': True
            },
            'x64dbg': {
                'name': 'x64dbg',
                'description': 'Debugger for Windows executables',
                'url': 'https://github.com/x64dbg/x64dbg/releases/latest',
                'install_method': 'download',
                'required': False,
                'platform': 'windows'
            },
            'qemu': {
                'name': 'QEMU',
                'description': 'Emulator for dynamic analysis',
                'install_method': 'system',
                'required': False
            },
            'frida': {
                'name': 'Frida',
                'description': 'Dynamic instrumentation toolkit',
                'install_method': 'pip',
                'required': True
            },
            'angr': {
                'name': 'Angr',
                'description': 'Symbolic execution framework',
                'install_method': 'pip',
                'required': True
            },
            'klee': {
                'name': 'KLEE',
                'description': 'Symbolic virtual machine',
                'url': 'https://github.com/klee/klee',
                'install_method': 'git',
                'required': False
            },
            'loki': {
                'name': 'Loki',
                'description': 'Malware classification and deobfuscation toolkit',
                'url': 'https://github.com/Neo23x0/Loki',
                'install_method': 'git',
                'required': False
            },
            'strings': {
                'name': 'Strings',
                'description': 'String extraction utility',
                'install_method': 'system',
                'required': True
            },
            'binwalk': {
                'name': 'Binwalk',
                'description': 'Binary firmware analysis tool',
                'install_method': 'pip',
                'required': True
            }
        }
    
    def _setup_logging(self):
        """Setup logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        return logging.getLogger('ToolInstaller')
    
    def install_all_tools(self):
        """Install all required tools"""
        self.logger.info("Starting tool installation...")
        
        # Install Python packages first
        self._install_python_packages()
        
        # Install system tools
        self._install_system_tools()
        
        # Install external tools
        self._install_external_tools()
        
        self.logger.info("Tool installation completed!")
    
    def _install_python_packages(self):
        """Install Python packages"""
        self.logger.info("Installing Python packages...")
        
        pip_tools = [
            'capstone', 'frida', 'frida-tools', 'angr', 'binwalk',
            'lief', 'pefile', 'pyelftools', 'python-magic', 'chardet',
            'scikit-learn', 'numpy', 'pandas', 'psutil', 'netaddr',
            'scapy', 'cryptography', 'pycryptodome', 'pyyaml', 'click',
            'colorama', 'tqdm', 'jinja2', 'markdown', 'loguru', 'rich'
        ]
        
        for tool in pip_tools:
            try:
                self.logger.info(f"Installing {tool}...")
                subprocess.run([sys.executable, '-m', 'pip', 'install', tool], 
                             check=True, capture_output=True)
                self.logger.info(f"✓ {tool} installed successfully")
            except subprocess.CalledProcessError as e:
                self.logger.error(f"✗ Failed to install {tool}: {e}")
    
    def _install_system_tools(self):
        """Install system tools"""
        self.logger.info("Installing system tools...")
        
        if self.system == 'linux':
            self._install_linux_tools()
        elif self.system == 'windows':
            self._install_windows_tools()
        elif self.system == 'darwin':
            self._install_macos_tools()
    
    def _install_linux_tools(self):
        """Install tools on Linux"""
        tools = {
            'apt': ['strings', 'binutils', 'qemu-system-x86', 'gdb', 'objdump', 'nm'],
            'yum': ['binutils', 'qemu-system-x86', 'gdb', 'objdump', 'nm'],
            'pacman': ['binutils', 'qemu-system-x86', 'gdb', 'objdump', 'nm']
        }
        
        # Try apt first
        try:
            subprocess.run(['apt', '--version'], check=True, capture_output=True)
            for tool in tools['apt']:
                try:
                    subprocess.run(['sudo', 'apt', 'install', '-y', tool], 
                                 check=True, capture_output=True)
                    self.logger.info(f"✓ {tool} installed via apt")
                except subprocess.CalledProcessError:
                    self.logger.warning(f"Failed to install {tool} via apt")
        except subprocess.CalledProcessError:
            pass
        
        # Try yum
        try:
            subprocess.run(['yum', '--version'], check=True, capture_output=True)
            for tool in tools['yum']:
                try:
                    subprocess.run(['sudo', 'yum', 'install', '-y', tool], 
                                 check=True, capture_output=True)
                    self.logger.info(f"✓ {tool} installed via yum")
                except subprocess.CalledProcessError:
                    self.logger.warning(f"Failed to install {tool} via yum")
        except subprocess.CalledProcessError:
            pass
    
    def _install_windows_tools(self):
        """Install tools on Windows"""
        self.logger.info("Windows tool installation requires manual setup")
        self.logger.info("Please install the following tools manually:")
        self.logger.info("- x64dbg: https://github.com/x64dbg/x64dbg/releases")
        self.logger.info("- QEMU: https://www.qemu.org/download/#windows")
        self.logger.info("- Strings: Part of Sysinternals Suite")
    
    def _install_macos_tools(self):
        """Install tools on macOS"""
        try:
            # Check if Homebrew is installed
            subprocess.run(['brew', '--version'], check=True, capture_output=True)
            
            tools = ['qemu', 'binutils', 'gdb', 'objdump', 'nm']
            for tool in tools:
                try:
                    subprocess.run(['brew', 'install', tool], 
                                 check=True, capture_output=True)
                    self.logger.info(f"✓ {tool} installed via Homebrew")
                except subprocess.CalledProcessError:
                    self.logger.warning(f"Failed to install {tool} via Homebrew")
        except subprocess.CalledProcessError:
            self.logger.error("Homebrew not found. Please install Homebrew first.")
    
    def _install_external_tools(self):
        """Install external tools"""
        self.logger.info("Installing external tools...")
        
        # Create tools directory
        tools_dir = Path('tools')
        tools_dir.mkdir(exist_ok=True)
        
        # Install Ghidra
        self._install_ghidra(tools_dir)
        
        # Install Radare2
        self._install_radare2(tools_dir)
        
        # Install KLEE (optional)
        self._install_klee(tools_dir)
        
        # Install Loki (optional)
        self._install_loki(tools_dir)
    
    def _install_ghidra(self, tools_dir):
        """Install Ghidra"""
        try:
            self.logger.info("Installing Ghidra...")
            
            # Download Ghidra
            ghidra_dir = tools_dir / 'ghidra'
            if ghidra_dir.exists():
                self.logger.info("Ghidra already installed")
                return
            
            # For demo purposes, we'll create a placeholder
            # In practice, you'd download from the official repository
            self.logger.info("Ghidra installation requires manual download")
            self.logger.info("Please download from: https://github.com/NationalSecurityAgency/ghidra/releases")
            
        except Exception as e:
            self.logger.error(f"Failed to install Ghidra: {e}")
    
    def _install_radare2(self, tools_dir):
        """Install Radare2"""
        try:
            self.logger.info("Installing Radare2...")
            
            radare2_dir = tools_dir / 'radare2'
            if radare2_dir.exists():
                self.logger.info("Radare2 already installed")
                return
            
            # Clone Radare2 repository
            subprocess.run([
                'git', 'clone', 'https://github.com/radareorg/radare2.git',
                str(radare2_dir)
            ], check=True, capture_output=True)
            
            # Build and install
            os.chdir(radare2_dir)
            subprocess.run(['./sys/install.sh'], check=True, capture_output=True)
            os.chdir('..')
            
            self.logger.info("✓ Radare2 installed successfully")
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to install Radare2: {e}")
        except Exception as e:
            self.logger.error(f"Error installing Radare2: {e}")
    
    def _install_klee(self, tools_dir):
        """Install KLEE"""
        try:
            self.logger.info("Installing KLEE...")
            
            klee_dir = tools_dir / 'klee'
            if klee_dir.exists():
                self.logger.info("KLEE already installed")
                return
            
            # KLEE installation is complex and requires LLVM
            self.logger.info("KLEE installation requires LLVM setup")
            self.logger.info("Please refer to: https://klee.github.io/getting-started/")
            
        except Exception as e:
            self.logger.error(f"Error installing KLEE: {e}")
    
    def _install_loki(self, tools_dir):
        """Install Loki"""
        try:
            self.logger.info("Installing Loki...")
            
            loki_dir = tools_dir / 'loki'
            if loki_dir.exists():
                self.logger.info("Loki already installed")
                return
            
            # Clone Loki repository
            subprocess.run([
                'git', 'clone', 'https://github.com/Neo23x0/Loki.git',
                str(loki_dir)
            ], check=True, capture_output=True)
            
            self.logger.info("✓ Loki installed successfully")
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to install Loki: {e}")
        except Exception as e:
            self.logger.error(f"Error installing Loki: {e}")
    
    def check_tool_availability(self):
        """Check which tools are available"""
        self.logger.info("Checking tool availability...")
        
        available_tools = {}
        
        for tool_name, config in self.tools_config.items():
            try:
                if config['install_method'] == 'pip':
                    # Check if Python package is available
                    try:
                        __import__(tool_name)
                        available_tools[tool_name] = True
                    except ImportError:
                        available_tools[tool_name] = False
                
                elif config['install_method'] == 'system':
                    # Check if system command is available
                    try:
                        subprocess.run([tool_name, '--version'], 
                                     check=True, capture_output=True)
                        available_tools[tool_name] = True
                    except (subprocess.CalledProcessError, FileNotFoundError):
                        available_tools[tool_name] = False
                
                else:
                    # Check if tool directory exists
                    tool_path = Path('tools') / tool_name
                    available_tools[tool_name] = tool_path.exists()
                
            except Exception as e:
                available_tools[tool_name] = False
                self.logger.warning(f"Error checking {tool_name}: {e}")
        
        return available_tools
    
    def generate_installation_report(self):
        """Generate installation report"""
        available_tools = self.check_tool_availability()
        
        report = {
            'system': {
                'platform': self.system,
                'architecture': self.arch,
                'python_version': sys.version
            },
            'tools': available_tools,
            'installation_status': 'completed' if all(available_tools.values()) else 'partial'
        }
        
        # Save report
        with open('installation_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info("Installation report saved to installation_report.json")
        return report

def main():
    """Main entry point"""
    installer = ToolInstaller()
    
    print("Reverse Engineering Automation Tool - Tool Installer")
    print("NTRO Approved - Government of India Project")
    print("=" * 60)
    
    try:
        # Install all tools
        installer.install_all_tools()
        
        # Generate report
        report = installer.generate_installation_report()
        
        # Print summary
        print("\nInstallation Summary:")
        print("-" * 20)
        for tool, available in report['tools'].items():
            status = "✓ Available" if available else "✗ Not Available"
            print(f"{tool:20} {status}")
        
        if report['installation_status'] == 'completed':
            print("\n✓ All tools installed successfully!")
        else:
            print("\n⚠ Some tools may require manual installation.")
            print("Please check the installation report for details.")
    
    except Exception as e:
        print(f"Error during installation: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
