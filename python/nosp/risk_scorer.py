"""
NOSP Risk Scoring Module
Advanced heuristic-based risk assessment for process events.
"""

from typing import Dict, List, Tuple
import re
from pathlib import Path


class RiskScorer:
    """
    Calculate risk scores for process events using multiple heuristics.
    Score range: 0-100 (0 = safe, 100 = critical threat)
    """
    
    # Suspicious patterns and their base risk points
    SUSPICIOUS_PATHS = {
        r'\\temp\\': 15,
        r'\\appdata\\local\\temp\\': 20,
        r'\\windows\\temp\\': 15,
        r'\\public\\': 10,
        r'\\users\\public\\': 15,
        r'\\programdata\\': 10,
        r'\\$recycle\.bin\\': 25,
    }
    
    SUSPICIOUS_EXTENSIONS = {
        '.vbs': 15,
        '.ps1': 10,
        '.bat': 10,
        '.cmd': 10,
        '.hta': 20,
        '.wsf': 20,
        '.jar': 10,
        '.scr': 25,
    }
    
    SUSPICIOUS_NAMES = {
        r'mimikatz': 40,
        r'procdump': 25,
        r'psexec': 20,
        r'netcat': 25,
        r'nc\.exe': 25,
        r'powershell.*encoded': 30,
        r'cmd.*\/c': 10,
        r'wscript': 15,
        r'cscript': 15,
        r'mshta': 20,
        r'regsvr32': 15,
        r'rundll32': 15,
        r'certutil': 20,
        r'bitsadmin': 20,
    }
    
    SUSPICIOUS_CMDLINE_PATTERNS = {
        r'-encodedcommand': 25,
        r'-enc': 25,
        r'invoke-expression': 20,
        r'iex': 20,
        r'downloadstring': 25,
        r'net user.*\/add': 30,
        r'net localgroup.*administrators.*\/add': 35,
        r'reg add.*run': 20,
        r'schtasks.*\/create': 20,
        r'wmic.*process.*call.*create': 25,
        r'bypass.*executionpolicy': 20,
        r'hidden.*windowstyle': 15,
    }
    
    TRUSTED_PARENTS = [
        'explorer.exe',
        'services.exe',
        'svchost.exe',
        'taskhost.exe',
        'taskhostw.exe',
    ]
    
    def __init__(self):
        """Initialize the risk scorer."""
        pass
    
    def calculate_risk(self, event: Dict) -> Tuple[int, List[Tuple[str, int, str]]]:
        """
        Calculate comprehensive risk score for an event.
        
        Args:
            event: Dictionary containing process event data
            
        Returns:
            Tuple of (total_risk_score, list of (factor_name, points, description))
        """
        risk_factors = []
        total_score = 0
        
        image = event.get('image', '').lower()
        cmdline = event.get('command_line', '').lower()
        parent_image = event.get('parent_image', '').lower()
        parent_cmdline = event.get('parent_command_line', '').lower()
        user = event.get('user', '').lower()
        
        # 1. Check file path suspicion
        path_score = self._check_path_risk(image)
        if path_score > 0:
            risk_factors.append(('suspicious_path', path_score, 
                                f'Process running from suspicious location'))
            total_score += path_score
        
        # 2. Check file extension
        ext_score = self._check_extension_risk(image)
        if ext_score > 0:
            risk_factors.append(('suspicious_extension', ext_score,
                                f'Suspicious file type detected'))
            total_score += ext_score
        
        # 3. Check process name
        name_score, name_desc = self._check_name_risk(image)
        if name_score > 0:
            risk_factors.append(('suspicious_name', name_score, name_desc))
            total_score += name_score
        
        # 4. Check command line patterns
        cmd_score, cmd_desc = self._check_cmdline_risk(cmdline)
        if cmd_score > 0:
            risk_factors.append(('suspicious_command', cmd_score, cmd_desc))
            total_score += cmd_score
        
        # 5. Check parent process relationship
        parent_score, parent_desc = self._check_parent_risk(image, parent_image, cmdline)
        if parent_score > 0:
            risk_factors.append(('suspicious_parent', parent_score, parent_desc))
            total_score += parent_score
        
        # 6. Check user context
        user_score = self._check_user_risk(user, image)
        if user_score > 0:
            risk_factors.append(('suspicious_user', user_score,
                                'Process running in unusual user context'))
            total_score += user_score
        
        # 7. Check for unsigned/missing hashes
        hash_score = self._check_hash_risk(event.get('hashes', {}))
        if hash_score > 0:
            risk_factors.append(('missing_signature', hash_score,
                                'Process lacks proper digital signatures'))
            total_score += hash_score
        
        # Cap score at 100
        total_score = min(total_score, 100)
        
        return total_score, risk_factors
    
    def _check_path_risk(self, image: str) -> int:
        """Check if process path is suspicious."""
        for pattern, score in self.SUSPICIOUS_PATHS.items():
            if re.search(pattern, image, re.IGNORECASE):
                return score
        return 0
    
    def _check_extension_risk(self, image: str) -> int:
        """Check if file extension is suspicious."""
        for ext, score in self.SUSPICIOUS_EXTENSIONS.items():
            if image.endswith(ext):
                return score
        return 0
    
    def _check_name_risk(self, image: str) -> Tuple[int, str]:
        """Check if process name matches known hacking tools."""
        for pattern, score in self.SUSPICIOUS_NAMES.items():
            if re.search(pattern, image, re.IGNORECASE):
                return score, f'Matches known security tool pattern: {pattern}'
        return 0, ''
    
    def _check_cmdline_risk(self, cmdline: str) -> Tuple[int, str]:
        """Check for suspicious command line patterns."""
        total_score = 0
        descriptions = []
        
        for pattern, score in self.SUSPICIOUS_CMDLINE_PATTERNS.items():
            if re.search(pattern, cmdline, re.IGNORECASE):
                total_score += score
                descriptions.append(pattern)
        
        if descriptions:
            desc = f'Suspicious command patterns: {", ".join(descriptions[:3])}'
            return total_score, desc
        return 0, ''
    
    def _check_parent_risk(self, image: str, parent_image: str, cmdline: str) -> Tuple[int, str]:
        """Check parent-child process relationship."""
        # PowerShell spawned by Office apps
        if 'powershell' in image and any(app in parent_image for app in ['winword', 'excel', 'outlook']):
            return 35, 'PowerShell spawned by Office application'
        
        # Scripting engines spawned by Office
        if any(script in image for script in ['wscript', 'cscript', 'mshta']) and \
           any(app in parent_image for app in ['winword', 'excel', 'outlook']):
            return 40, 'Script engine spawned by Office application'
        
        # cmd.exe spawned by suspicious parents
        if 'cmd.exe' in image and parent_image and \
           not any(trusted in parent_image for trusted in self.TRUSTED_PARENTS):
            return 10, 'cmd.exe spawned by non-standard parent'
        
        # Suspicious parent-child combo
        if 'powershell' in image and 'cmd.exe' in parent_image and '-enc' in cmdline:
            return 30, 'Encoded PowerShell from cmd.exe'
        
        return 0, ''
    
    def _check_user_risk(self, user: str, image: str) -> int:
        """Check user context for anomalies."""
        # System processes running as regular user
        system_processes = ['smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe']
        if any(proc in image for proc in system_processes) and 'system' not in user:
            return 30
        
        # SYSTEM running user-mode apps
        if 'system' in user and any(app in image for app in ['notepad', 'calc', 'mspaint']):
            return 15
        
        return 0
    
    def _check_hash_risk(self, hashes: Dict) -> int:
        """Check for missing or suspicious hashes."""
        if not hashes or len(hashes) == 0:
            return 10
        return 0
    
    def get_risk_level(self, score: int) -> str:
        """Convert numeric score to risk level."""
        if score >= 75:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        elif score >= 10:
            return "LOW"
        else:
            return "MINIMAL"
    
    def get_risk_color(self, score: int) -> str:
        """Get color code for risk level (for UI)."""
        if score >= 75:
            return "#FF4444"  # Red
        elif score >= 60:
            return "#FF8800"  # Orange
        elif score >= 30:
            return "#FFCC00"  # Yellow
        elif score >= 10:
            return "#88FF88"  # Light green
        else:
            return "#00FF00"  # Green
