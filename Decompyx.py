#!/usr/bin/env python3
"""
Reverse Engineering Automation Tool
NTRO Approved - Government of India Project

This tool automates various reverse engineering techniques using open-source tools:
- Static Analysis (Ghidra, Radare2, Capstone)
- Dynamic Analysis (x64dbg, QEMU, Frida)
- Symbolic Execution (Angr, KLEE)
- Automated Deobfuscation (Loki, Dfsan)
- String and Data Mining (strings, Binwalk)
"""

import os
import sys
import json
import subprocess
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

# Import our analysis modules
from modules.static_analysis import StaticAnalyzer
from modules.dynamic_analysis import DynamicAnalyzer
from modules.symbolic_execution import SymbolicExecutor
from modules.deobfuscation import DeobfuscationEngine
from modules.string_mining import StringMiner
from utils.config_manager import ConfigManager
from utils.report_generator import ReportGenerator

class ReverseEngineeringAutomation:
    """
    Main automation class that orchestrates all reverse engineering tasks
    """
    
    def __init__(self, config_file: str = "config.json"):
        self.config = ConfigManager(config_file)
        self.logger = self._setup_logging()
        self.results = {}
        
        # Initialize analysis modules
        self.static_analyzer = StaticAnalyzer(self.config)
        self.dynamic_analyzer = DynamicAnalyzer(self.config)
        self.symbolic_executor = SymbolicExecutor(self.config)
        self.deobfuscation_engine = DeobfuscationEngine(self.config)
        self.string_miner = StringMiner(self.config)
        
        self.report_generator = ReportGenerator()
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('RE_Automation')
        logger.setLevel(logging.INFO)
        
        # Create logs directory if it doesn't exist
        os.makedirs('logs', exist_ok=True)
        
        # File handler
        fh = logging.FileHandler(f'logs/re_automation_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
        fh.setLevel(logging.INFO)
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        logger.addHandler(fh)
        logger.addHandler(ch)
        
        return logger
    
    def analyze_target(self, target_path: str, analysis_types: List[str] = None) -> Dict[str, Any]:
        """
        Perform comprehensive reverse engineering analysis on target
        
        Args:
            target_path: Path to the target binary/executable
            analysis_types: List of analysis types to perform (None = all)
        
        Returns:
            Dictionary containing all analysis results
        """
        if not os.path.exists(target_path):
            raise FileNotFoundError(f"Target file not found: {target_path}")
        
        self.logger.info(f"Starting analysis of target: {target_path}")
        
        if analysis_types is None:
            analysis_types = ['static', 'dynamic', 'symbolic', 'deobfuscation', 'string_mining']
        
        results = {
            'target': target_path,
            'timestamp': datetime.now().isoformat(),
            'analysis_types': analysis_types,
            'results': {}
        }
        
        try:
            # Static Analysis
            if 'static' in analysis_types:
                self.logger.info("Performing static analysis...")
                results['results']['static'] = self.static_analyzer.analyze(target_path)
            
            # Dynamic Analysis
            if 'dynamic' in analysis_types:
                self.logger.info("Performing dynamic analysis...")
                results['results']['dynamic'] = self.dynamic_analyzer.analyze(target_path)
            
            # Symbolic Execution
            if 'symbolic' in analysis_types:
                self.logger.info("Performing symbolic execution...")
                results['results']['symbolic'] = self.symbolic_executor.analyze(target_path)
            
            # Deobfuscation
            if 'deobfuscation' in analysis_types:
                self.logger.info("Performing deobfuscation analysis...")
                results['results']['deobfuscation'] = self.deobfuscation_engine.analyze(target_path)
            
            # String Mining
            if 'string_mining' in analysis_types:
                self.logger.info("Performing string and data mining...")
                results['results']['string_mining'] = self.string_miner.analyze(target_path)
            
            # Generate comprehensive report
            report_path = self.report_generator.generate_report(results)
            results['report_path'] = report_path
            
            self.logger.info(f"Analysis completed. Report saved to: {report_path}")
            
        except Exception as e:
            self.logger.error(f"Error during analysis: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def quick_scan(self, target_path: str) -> Dict[str, Any]:
        """
        Perform a quick scan using basic tools (strings, file info, etc.)
        
        Args:
            target_path: Path to the target binary
        
        Returns:
            Dictionary containing quick scan results
        """
        self.logger.info(f"Performing quick scan of: {target_path}")
        
        results = {
            'target': target_path,
            'timestamp': datetime.now().isoformat(),
            'scan_type': 'quick',
            'results': {}
        }
        
        try:
            # Basic file information
            results['results']['file_info'] = self._get_file_info(target_path)
            
            # String extraction
            results['results']['strings'] = self.string_miner.extract_strings(target_path)
            
            # Basic static analysis
            results['results']['basic_static'] = self.static_analyzer.quick_analysis(target_path)
            
        except Exception as e:
            self.logger.error(f"Error during quick scan: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def _get_file_info(self, target_path: str) -> Dict[str, Any]:
        """Get basic file information"""
        stat = os.stat(target_path)
        return {
            'size': stat.st_size,
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'permissions': oct(stat.st_mode),
            'extension': Path(target_path).suffix
        }

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Reverse Engineering Automation Tool - NTRO Approved')
    parser.add_argument('target', help='Path to target binary/executable')
    parser.add_argument('--analysis-types', nargs='+', 
                       choices=['static', 'dynamic', 'symbolic', 'deobfuscation', 'string_mining'],
                       help='Types of analysis to perform (default: all)')
    parser.add_argument('--quick', action='store_true', help='Perform quick scan only')
    parser.add_argument('--config', default='config.json', help='Configuration file path')
    parser.add_argument('--output', help='Output directory for results')
    
    args = parser.parse_args()
    
    try:
        # Initialize automation tool
        re_tool = ReverseEngineeringAutomation(args.config)
        
        if args.quick:
            results = re_tool.quick_scan(args.target)
        else:
            results = re_tool.analyze_target(args.target, args.analysis_types)
        
        # Save results
        output_dir = args.output or 'results'
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = os.path.join(output_dir, f'analysis_results_{timestamp}.json')
        
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"Analysis completed. Results saved to: {results_file}")
        
        if 'report_path' in results:
            print(f"Comprehensive report: {results['report_path']}")
    
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
