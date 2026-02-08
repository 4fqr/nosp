"""
NOSP Forensics Module
Advanced forensic analysis, process tree visualization, and PDF report generation.
"""

import networkx as nx
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta
import json
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    from fpdf import FPDF
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    logger.warning("⚠ FPDF not available. Install with: pip install fpdf2")


class ProcessTree:
    """
    Build and analyze process parent-child relationships.
    """
    
    def __init__(self):
        """Initialize the process tree."""
        self.graph = nx.DiGraph()
        self.process_data = {}
    
    def add_process(self, event: Dict):
        """Add a process to the tree."""
        process_id = event.get('process_id')
        process_guid = event.get('process_guid', '')
        image = event.get('image', 'unknown')
        parent_image = event.get('parent_image', 'unknown')
        risk_score = event.get('risk_score', 0)
        
        # Store process data
        self.process_data[process_id] = {
            'guid': process_guid,
            'image': image,
            'parent': parent_image,
            'risk': risk_score,
            'timestamp': event.get('timestamp', ''),
            'cmdline': event.get('command_line', '')
        }
        
        # Add node to graph
        self.graph.add_node(
            process_id,
            label=Path(image).name,
            risk=risk_score,
            full_path=image
        )
        
        # Try to find parent and create edge
        # This is simplified - real implementation needs parent PID tracking
        for pid, data in self.process_data.items():
            if data['image'].lower() in parent_image.lower() and pid != process_id:
                self.graph.add_edge(pid, process_id)
                break
    
    def get_tree_data(self) -> Dict:
        """Get tree data for visualization."""
        nodes = []
        edges = []
        
        for node_id, node_data in self.graph.nodes(data=True):
            nodes.append({
                'id': node_id,
                'label': node_data.get('label', str(node_id)),
                'risk': node_data.get('risk', 0),
                'path': node_data.get('full_path', '')
            })
        
        for source, target in self.graph.edges():
            edges.append({
                'source': source,
                'target': target
            })
        
        return {'nodes': nodes, 'edges': edges}
    
    def find_suspicious_chains(self, min_risk: int = 50) -> List[List[int]]:
        """Find process chains with high risk scores."""
        suspicious = []
        
        for node in self.graph.nodes():
            if self.graph.nodes[node].get('risk', 0) >= min_risk:
                # Get all paths from root to this node
                try:
                    roots = [n for n in self.graph.nodes() if self.graph.in_degree(n) == 0]
                    for root in roots:
                        if nx.has_path(self.graph, root, node):
                            path = nx.shortest_path(self.graph, root, node)
                            if len(path) > 1:  # Only multi-node chains
                                suspicious.append(path)
                except:
                    pass
        
        return suspicious
    
    def get_process_lineage(self, pid: int) -> List[Dict]:
        """Get the full lineage of a process."""
        lineage = []
        
        if pid not in self.process_data:
            return lineage
        
        # Traverse upwards
        current = pid
        visited = set()
        
        while current and current not in visited:
            visited.add(current)
            if current in self.process_data:
                lineage.append(self.process_data[current])
                
                # Find parent
                for edge in self.graph.in_edges(current):
                    current = edge[0]
                    break
                else:
                    break
            else:
                break
        
        return lineage[::-1]  # Reverse to show from parent to child


class ForensicReporter:
    """
    Generate professional PDF forensic reports.
    """
    
    def __init__(self):
        """Initialize the reporter."""
        if not PDF_AVAILABLE:
            raise ImportError("FPDF not available. Install with: pip install fpdf2")
    
    def generate_incident_report(self, 
                                  events: List[Dict], 
                                  stats: Dict,
                                  output_path: str = None) -> str:
        """
        Generate a comprehensive incident report PDF.
        
        Args:
            events: List of security events
            stats: Statistics dictionary
            output_path: Path to save PDF (auto-generates if None)
            
        Returns:
            Path to generated PDF file
        """
        pdf = FPDF()
        pdf.add_page()
        
        # Header
        pdf.set_font('Arial', 'B', 24)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 20, 'NOSP SECURITY INCIDENT REPORT', 0, 1, 'C')
        
        # Timestamp
        pdf.set_font('Arial', '', 10)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 10, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'C')
        pdf.ln(10)
        
        # Executive Summary
        pdf.set_font('Arial', 'B', 16)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 10, 'EXECUTIVE SUMMARY', 0, 1)
        pdf.set_font('Arial', '', 12)
        
        summary_data = [
            f"Total Events Analyzed: {stats.get('total_events', 0)}",
            f"High-Risk Events: {stats.get('high_risk_events', 0)}",
            f"Critical Threats: {len([e for e in events if e.get('risk_score', 0) >= 75])}",
            f"Average Risk Score: {stats.get('avg_risk_score', 0):.2f}",
            f"Time Period: Last 24 hours"
        ]
        
        for line in summary_data:
            pdf.cell(0, 8, line, 0, 1)
        pdf.ln(10)
        
        # High-Risk Events Table
        if events:
            pdf.set_font('Arial', 'B', 16)
            pdf.cell(0, 10, 'HIGH-RISK EVENTS DETECTED', 0, 1)
            pdf.set_font('Arial', 'B', 10)
            
            # Table header
            pdf.cell(30, 8, 'Risk Score', 1, 0, 'C')
            pdf.cell(50, 8, 'Process', 1, 0, 'C')
            pdf.cell(50, 8, 'User', 1, 0, 'C')
            pdf.cell(60, 8, 'Timestamp', 1, 1, 'C')
            
            pdf.set_font('Arial', '', 9)
            
            # Table rows (top 20 high-risk events)
            for event in sorted(events, key=lambda x: x.get('risk_score', 0), reverse=True)[:20]:
                risk = event.get('risk_score', 0)
                
                # Color code by risk
                if risk >= 75:
                    pdf.set_fill_color(255, 200, 200)
                elif risk >= 60:
                    pdf.set_fill_color(255, 230, 200)
                elif risk >= 30:
                    pdf.set_fill_color(255, 255, 200)
                else:
                    pdf.set_fill_color(255, 255, 255)
                
                process_name = Path(event.get('image', 'unknown')).name[:20]
                user = event.get('user', 'unknown')[:20]
                timestamp = event.get('timestamp', '')[:19]
                
                pdf.cell(30, 8, str(risk), 1, 0, 'C', True)
                pdf.cell(50, 8, process_name, 1, 0, 'L', True)
                pdf.cell(50, 8, user, 1, 0, 'L', True)
                pdf.cell(60, 8, timestamp, 1, 1, 'L', True)
        
        pdf.ln(10)
        
        # Recommendations
        pdf.add_page()
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'RECOMMENDATIONS', 0, 1)
        pdf.set_font('Arial', '', 11)
        
        recommendations = self._generate_recommendations(events, stats)
        for rec in recommendations:
            pdf.multi_cell(0, 8, f'• {rec}')
            pdf.ln(2)
        
        # Footer
        pdf.ln(20)
        pdf.set_font('Arial', 'I', 10)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 10, 'NOSP - Null OS Security Program', 0, 1, 'C')
        pdf.cell(0, 5, 'Confidential Security Report', 0, 1, 'C')
        
        # Save PDF
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"nosp_data/incident_report_{timestamp}.pdf"
        
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        pdf.output(output_path)
        
        logger.info(f"✓ PDF report generated: {output_path}")
        return output_path
    
    def _generate_recommendations(self, events: List[Dict], stats: Dict) -> List[str]:
        """Generate security recommendations based on events."""
        recommendations = []
        
        high_risk_count = stats.get('high_risk_events', 0)
        
        if high_risk_count > 10:
            recommendations.append(
                "CRITICAL: Multiple high-risk events detected. Immediate investigation required."
            )
        
        if high_risk_count > 0:
            recommendations.append(
                "Review and analyze all high-risk events for potential security breaches."
            )
        
        # Check for common attack patterns
        powershell_count = len([e for e in events if 'powershell' in e.get('image', '').lower()])
        if powershell_count > 5:
            recommendations.append(
                f"PowerShell activity detected ({powershell_count} instances). Review for malicious scripts."
            )
        
        # Check for Office spawning processes
        office_spawns = [e for e in events if any(app in e.get('parent_image', '').lower() 
                                                   for app in ['winword', 'excel', 'outlook'])]
        if office_spawns:
            recommendations.append(
                f"Office applications spawned {len(office_spawns)} processes. Check for macro-based attacks."
            )
        
        recommendations.extend([
            "Ensure all systems have the latest security patches installed.",
            "Review user access controls and implement principle of least privilege.",
            "Enable advanced logging and monitoring on critical systems.",
            "Conduct security awareness training for users showing risky behavior."
        ])
        
        return recommendations


class TimelineAnalyzer:
    """
    Analyze events timeline for patterns and anomalies.
    """
    
    def __init__(self, events: List[Dict]):
        """Initialize with event data."""
        self.events = sorted(events, key=lambda x: x.get('timestamp', ''))
    
    def get_hourly_distribution(self) -> Dict[int, int]:
        """Get event count distribution by hour."""
        distribution = {hour: 0 for hour in range(24)}
        
        for event in self.events:
            try:
                timestamp = event.get('timestamp', '')
                if timestamp:
                    hour = datetime.fromisoformat(timestamp).hour
                    distribution[hour] += 1
            except:
                pass
        
        return distribution
    
    def detect_burst_activity(self, window_minutes: int = 5, threshold: int = 10) -> List[Dict]:
        """Detect burst activity (many events in short time)."""
        bursts = []
        
        if not self.events:
            return bursts
        
        window = timedelta(minutes=window_minutes)
        
        for i, event in enumerate(self.events):
            try:
                event_time = datetime.fromisoformat(event.get('timestamp', ''))
                count = 1
                
                # Count events within window
                for j in range(i + 1, len(self.events)):
                    next_time = datetime.fromisoformat(self.events[j].get('timestamp', ''))
                    if next_time - event_time <= window:
                        count += 1
                    else:
                        break
                
                if count >= threshold:
                    bursts.append({
                        'timestamp': event.get('timestamp'),
                        'count': count,
                        'window_minutes': window_minutes
                    })
            except:
                pass
        
        return bursts
    
    def find_process_sequences(self, process_names: List[str]) -> List[List[Dict]]:
        """Find sequences where specific processes appear in order."""
        sequences = []
        
        process_names_lower = [p.lower() for p in process_names]
        
        for i, event in enumerate(self.events):
            image = Path(event.get('image', '')).name.lower()
            
            if image == process_names_lower[0]:
                # Start of potential sequence
                sequence = [event]
                next_idx = 1
                
                # Look ahead for remaining processes
                for j in range(i + 1, min(i + 100, len(self.events))):
                    next_image = Path(self.events[j].get('image', '')).name.lower()
                    if next_image == process_names_lower[next_idx]:
                        sequence.append(self.events[j])
                        next_idx += 1
                        
                        if next_idx >= len(process_names_lower):
                            sequences.append(sequence)
                            break
        
        return sequences
