#!/usr/bin/env python3
"""
Report Generator
NTRO Approved - Government of India Project

This module generates comprehensive reports from reverse engineering analysis results
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import html

class ReportGenerator:
    """
    Report generator for reverse engineering analysis results
    """
    
    def __init__(self):
        self.logger = logging.getLogger('ReportGenerator')
        
        # Create reports directory
        self.reports_dir = 'reports'
        os.makedirs(self.reports_dir, exist_ok=True)
    
    def generate_report(self, analysis_results: Dict[str, Any]) -> str:
        """
        Generate comprehensive report from analysis results
        
        Args:
            analysis_results: Dictionary containing analysis results
        
        Returns:
            Path to generated report file
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_name = Path(analysis_results.get('target', 'unknown')).stem
            report_filename = f"re_analysis_report_{target_name}_{timestamp}.html"
            report_path = os.path.join(self.reports_dir, report_filename)
            
            # Generate HTML report
            html_content = self._generate_html_report(analysis_results)
            
            # Save report
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            # Generate JSON report
            json_report_path = report_path.replace('.html', '.json')
            with open(json_report_path, 'w', encoding='utf-8') as f:
                json.dump(analysis_results, f, indent=2, default=str)
            
            self.logger.info(f"Report generated: {report_path}")
            return report_path
            
        except Exception as e:
            self.logger.error(f"Error generating report: {str(e)}")
            raise
    
    def _generate_html_report(self, results: Dict[str, Any]) -> str:
        """Generate HTML report content"""
        try:
            target = results.get('target', 'Unknown')
            timestamp = results.get('timestamp', datetime.now().isoformat())
            analysis_types = results.get('analysis_types', [])
            
            html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reverse Engineering Analysis Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            border-bottom: 3px solid #2c3e50;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #2c3e50;
            margin: 0;
            font-size: 2.5em;
        }}
        .header .subtitle {{
            color: #7f8c8d;
            margin: 10px 0;
            font-size: 1.2em;
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .info-card {{
            background-color: #ecf0f1;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #3498db;
        }}
        .info-card h3 {{
            margin: 0 0 10px 0;
            color: #2c3e50;
        }}
        .section {{
            margin-bottom: 40px;
            padding: 20px;
            background-color: #f8f9fa;
            border-radius: 8px;
            border: 1px solid #dee2e6;
        }}
        .section h2 {{
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}
        .analysis-type {{
            background-color: white;
            margin: 15px 0;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #e74c3c;
        }}
        .analysis-type h3 {{
            margin: 0 0 10px 0;
            color: #e74c3c;
        }}
        .tools-used {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin: 10px 0;
        }}
        .tool-tag {{
            background-color: #3498db;
            color: white;
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 0.9em;
        }}
        .results-content {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-top: 10px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            white-space: pre-wrap;
            overflow-x: auto;
        }}
        .error {{
            background-color: #f8d7da;
            color: #721c24;
            padding: 15px;
            border-radius: 5px;
            border: 1px solid #f5c6cb;
            margin: 10px 0;
        }}
        .success {{
            background-color: #d4edda;
            color: #155724;
            padding: 15px;
            border-radius: 5px;
            border: 1px solid #c3e6cb;
            margin: 10px 0;
        }}
        .warning {{
            background-color: #fff3cd;
            color: #856404;
            padding: 15px;
            border-radius: 5px;
            border: 1px solid #ffeaa7;
            margin: 10px 0;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
            color: #6c757d;
        }}
        .collapsible {{
            background-color: #3498db;
            color: white;
            cursor: pointer;
            padding: 10px;
            width: 100%;
            border: none;
            text-align: left;
            outline: none;
            font-size: 1em;
            border-radius: 5px;
            margin: 5px 0;
        }}
        .collapsible:hover {{
            background-color: #2980b9;
        }}
        .collapsible:after {{
            content: '\\002B';
            color: white;
            font-weight: bold;
            float: right;
            margin-left: 5px;
        }}
        .collapsible.active:after {{
            content: "\\2212";
        }}
        .content {{
            padding: 0 18px;
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.2s ease-out;
            background-color: #f1f1f1;
            border-radius: 0 0 5px 5px;
        }}
        .content.active {{
            max-height: 1000px;
            padding: 18px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Reverse Engineering Analysis Report</h1>
            <div class="subtitle">NTRO Approved - Government of India Project</div>
        </div>
        
        <div class="info-grid">
            <div class="info-card">
                <h3>Target Information</h3>
                <p><strong>File:</strong> {html.escape(str(target))}</p>
                <p><strong>Analysis Date:</strong> {html.escape(timestamp)}</p>
                <p><strong>Analysis Types:</strong> {', '.join(analysis_types)}</p>
            </div>
            
            <div class="info-card">
                <h3>Analysis Summary</h3>
                <p><strong>Total Analysis Types:</strong> {len(analysis_types)}</p>
                <p><strong>Status:</strong> {'Completed' if 'error' not in results else 'Failed'}</p>
                <p><strong>Report Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        </div>
"""
            
            # Add analysis results sections
            if 'results' in results:
                html_content += self._generate_analysis_sections(results['results'])
            
            # Add error section if present
            if 'error' in results:
                html_content += f"""
        <div class="section">
            <h2>Analysis Errors</h2>
            <div class="error">
                <strong>Error:</strong> {html.escape(str(results['error']))}
            </div>
        </div>
"""
            
            # Add footer
            html_content += """
        <div class="footer">
            <p>Generated by Reverse Engineering Automation Tool v1.0.0</p>
            <p>NTRO - Government of India | Approved for Security Research</p>
        </div>
    </div>
    
    <script>
        var coll = document.getElementsByClassName("collapsible");
        var i;
        
        for (i = 0; i < coll.length; i++) {
            coll[i].addEventListener("click", function() {
                this.classList.toggle("active");
                var content = this.nextElementSibling;
                if (content.style.maxHeight) {
                    content.style.maxHeight = null;
                } else {
                    content.style.maxHeight = content.scrollHeight + "px";
                }
            });
        }
    </script>
</body>
</html>
"""
            
            return html_content
            
        except Exception as e:
            self.logger.error(f"Error generating HTML report: {str(e)}")
            raise
    
    def _generate_analysis_sections(self, results: Dict[str, Any]) -> str:
        """Generate analysis sections HTML"""
        html_content = ""
        
        for analysis_type, analysis_results in results.items():
            if not analysis_results:
                continue
            
            html_content += f"""
        <div class="section">
            <h2>{analysis_type.replace('_', ' ').title()} Analysis</h2>
"""
            
            # Add tools used
            if 'tools_used' in analysis_results:
                tools = analysis_results['tools_used']
                html_content += f"""
            <div class="tools-used">
                <strong>Tools Used:</strong>
                {''.join([f'<span class="tool-tag">{tool}</span>' for tool in tools])}
            </div>
"""
            
            # Add analysis results
            if 'results' in analysis_results:
                html_content += self._generate_results_html(analysis_results['results'], analysis_type)
            
            # Add error if present
            if 'error' in analysis_results:
                html_content += f"""
            <div class="error">
                <strong>Error in {analysis_type}:</strong> {html.escape(str(analysis_results['error']))}
            </div>
"""
            
            html_content += "</div>"
        
        return html_content
    
    def _generate_results_html(self, results: Dict[str, Any], analysis_type: str) -> str:
        """Generate results HTML content"""
        html_content = ""
        
        for result_type, result_data in results.items():
            if not result_data:
                continue
            
            html_content += f"""
            <button class="collapsible">{result_type.replace('_', ' ').title()}</button>
            <div class="content">
                <div class="results-content">{self._format_result_data(result_data)}</div>
            </div>
"""
        
        return html_content
    
    def _format_result_data(self, data: Any) -> str:
        """Format result data for display"""
        try:
            if isinstance(data, dict):
                return json.dumps(data, indent=2, default=str)
            elif isinstance(data, list):
                if data and isinstance(data[0], dict):
                    return json.dumps(data, indent=2, default=str)
                else:
                    return '\n'.join([str(item) for item in data])
            else:
                return str(data)
        except Exception as e:
            return f"Error formatting data: {str(e)}"
    
    def generate_summary_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate a summary report"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_name = Path(analysis_results.get('target', 'unknown')).stem
            summary_filename = f"re_analysis_summary_{target_name}_{timestamp}.txt"
            summary_path = os.path.join(self.reports_dir, summary_filename)
            
            summary_content = self._generate_summary_content(analysis_results)
            
            with open(summary_path, 'w', encoding='utf-8') as f:
                f.write(summary_content)
            
            self.logger.info(f"Summary report generated: {summary_path}")
            return summary_path
            
        except Exception as e:
            self.logger.error(f"Error generating summary report: {str(e)}")
            raise
    
    def _generate_summary_content(self, results: Dict[str, Any]) -> str:
        """Generate summary report content"""
        target = results.get('target', 'Unknown')
        timestamp = results.get('timestamp', datetime.now().isoformat())
        analysis_types = results.get('analysis_types', [])
        
        summary = f"""
Reverse Engineering Analysis Summary
====================================

Target: {target}
Analysis Date: {timestamp}
Analysis Types: {', '.join(analysis_types)}

Analysis Results:
"""
        
        if 'results' in results:
            for analysis_type, analysis_results in results['results'].items():
                summary += f"\n{analysis_type.upper()} ANALYSIS:\n"
                summary += "-" * (len(analysis_type) + 10) + "\n"
                
                if 'tools_used' in analysis_results:
                    summary += f"Tools Used: {', '.join(analysis_results['tools_used'])}\n"
                
                if 'results' in analysis_results:
                    for result_type, result_data in analysis_results['results'].items():
                        summary += f"\n{result_type}:\n"
                        if isinstance(result_data, dict):
                            for key, value in result_data.items():
                                if isinstance(value, list):
                                    summary += f"  {key}: {len(value)} items\n"
                                else:
                                    summary += f"  {key}: {value}\n"
                        else:
                            summary += f"  {result_data}\n"
                
                if 'error' in analysis_results:
                    summary += f"Error: {analysis_results['error']}\n"
                
                summary += "\n"
        
        if 'error' in results:
            summary += f"\nOVERALL ERROR: {results['error']}\n"
        
        summary += f"\nReport Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        summary += "NTRO - Government of India | Approved for Security Research\n"
        
        return summary
    
    def generate_json_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate JSON report"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_name = Path(analysis_results.get('target', 'unknown')).stem
            json_filename = f"re_analysis_results_{target_name}_{timestamp}.json"
            json_path = os.path.join(self.reports_dir, json_filename)
            
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(analysis_results, f, indent=2, default=str)
            
            self.logger.info(f"JSON report generated: {json_path}")
            return json_path
            
        except Exception as e:
            self.logger.error(f"Error generating JSON report: {str(e)}")
            raise
