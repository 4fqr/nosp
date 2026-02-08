"""
NOSP vAPEX - Embedded Web Terminal
Execute system commands directly from the NOSP interface
"""

import subprocess
import logging
import re
from typing import Tuple, List, Optional
from datetime import datetime
from pathlib import Path
import shlex

logger = logging.getLogger(__name__)


class CommandSanitizer:
    """Sanitizes and validates commands for safe execution"""
    
    # Dangerous commands that should be blocked
    BLACKLIST = {
        'format', 'del', 'rd', 'rmdir', 'deltree',
        'shutdown', 'restart', 'reboot',
        'reg delete', 'wmic',
        'taskkill /f',  # Allow regular taskkill but not force
    }
    
    # Commands that require explicit confirmation
    REQUIRE_CONFIRMATION = {
        'taskkill', 'net stop', 'net start',
        'sc stop', 'sc delete'
    }
    
    @staticmethod
    def is_safe(command: str) -> Tuple[bool, Optional[str]]:
        """
        Check if command is safe to execute
        
        Returns:
            Tuple of (is_safe, reason_if_unsafe)
        """
        cmd_lower = command.lower().strip()
        
        # Check blacklist
        for dangerous in CommandSanitizer.BLACKLIST:
            if dangerous in cmd_lower:
                return False, f"Blocked dangerous command: {dangerous}"
        
        # Check for command injection attempts
        suspicious_chars = ['&', '|', ';', '`', '$', '(', ')']
        for char in suspicious_chars:
            if char in command and char != '|':  # Allow pipes
                return False, f"Suspicious character detected: {char}"
        
        # Check for path traversal
        if '..' in command or '~' in command:
            return False, "Path traversal detected"
        
        return True, None
    
    @staticmethod
    def needs_confirmation(command: str) -> bool:
        """Check if command requires user confirmation"""
        cmd_lower = command.lower().strip()
        
        for sensitive in CommandSanitizer.REQUIRE_CONFIRMATION:
            if cmd_lower.startswith(sensitive):
                return True
        
        return False


class TerminalSession:
    """
    Embedded terminal session manager
    
    Features:
    - Execute Windows commands (cmd, PowerShell, ping, netstat, etc.)
    - Command history
    - Output formatting
    - Safety checks
    """
    
    def __init__(self, max_history: int = 100):
        self.history: List[Dict] = []
        self.max_history = max_history
        self.working_directory = Path.cwd()
        self.shell = "cmd"  # or "powershell"
    
    def execute_command(self, command: str, timeout: int = 30) -> Dict:
        """
        Execute a command safely
        
        Args:
            command: Command string to execute
            timeout: Max execution time in seconds
        
        Returns:
            Dictionary with execution results
        """
        timestamp = datetime.now().isoformat()
        
        # Sanitize command
        is_safe, reason = CommandSanitizer.is_safe(command)
        if not is_safe:
            result = {
                'timestamp': timestamp,
                'command': command,
                'success': False,
                'stdout': '',
                'stderr': f"BLOCKED: {reason}",
                'returncode': -1,
                'duration': 0
            }
            self._add_to_history(result)
            return result
        
        # Execute command
        start_time = datetime.now()
        
        try:
            if self.shell == "powershell":
                # PowerShell execution
                full_command = ["powershell", "-Command", command]
            else:
                # CMD execution
                full_command = ["cmd", "/c", command]
            
            proc = subprocess.run(
                full_command,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(self.working_directory)
            )
            
            duration = (datetime.now() - start_time).total_seconds()
            
            result = {
                'timestamp': timestamp,
                'command': command,
                'success': proc.returncode == 0,
                'stdout': proc.stdout,
                'stderr': proc.stderr,
                'returncode': proc.returncode,
                'duration': duration
            }
            
        except subprocess.TimeoutExpired:
            duration = timeout
            result = {
                'timestamp': timestamp,
                'command': command,
                'success': False,
                'stdout': '',
                'stderr': f"Command timed out after {timeout} seconds",
                'returncode': -1,
                'duration': duration
            }
            
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            result = {
                'timestamp': timestamp,
                'command': command,
                'success': False,
                'stdout': '',
                'stderr': str(e),
                'returncode': -1,
                'duration': duration
            }
        
        # Add to history
        self._add_to_history(result)
        
        logger.info(f"Executed: {command} (success: {result['success']})")
        return result
    
    def _add_to_history(self, result: Dict):
        """Add command result to history"""
        self.history.append(result)
        
        # Trim history if needed
        if len(self.history) > self.max_history:
            self.history.pop(0)
    
    def get_history(self, limit: Optional[int] = None) -> List[Dict]:
        """Get command history"""
        if limit:
            return self.history[-limit:]
        return self.history.copy()
    
    def clear_history(self):
        """Clear command history"""
        self.history.clear()
        logger.info("Terminal history cleared")
    
    def change_directory(self, path: str) -> bool:
        """Change working directory"""
        try:
            new_path = Path(path).resolve()
            if new_path.exists() and new_path.is_dir():
                self.working_directory = new_path
                logger.info(f"Changed directory to: {new_path}")
                return True
            else:
                logger.error(f"Directory not found: {path}")
                return False
        except Exception as e:
            logger.error(f"Failed to change directory: {e}")
            return False
    
    def get_working_directory(self) -> str:
        """Get current working directory"""
        return str(self.working_directory)
    
    def switch_shell(self, shell: str):
        """Switch between cmd and powershell"""
        if shell.lower() in ['cmd', 'powershell']:
            self.shell = shell.lower()
            logger.info(f"Switched to {shell}")
        else:
            logger.warning(f"Unknown shell: {shell}")
    
    def get_suggestions(self, partial_command: str) -> List[str]:
        """Get command suggestions based on partial input"""
        common_commands = [
            'ping', 'ipconfig', 'netstat', 'tracert', 'nslookup',
            'dir', 'cd', 'cls', 'echo', 'type', 'find',
            'tasklist', 'taskkill', 'systeminfo', 'whoami',
            'net user', 'net localgroup', 'net share',
            'sfc /scannow', 'chkdsk', 'diskpart',
            'Get-Process', 'Get-Service', 'Get-EventLog',
            'Get-NetAdapter', 'Get-NetIPConfiguration'
        ]
        
        partial_lower = partial_command.lower()
        return [cmd for cmd in common_commands if cmd.lower().startswith(partial_lower)]


# Pre-defined command templates for common tasks
COMMAND_TEMPLATES = {
    'Network Diagnostics': {
        'Ping Google': 'ping google.com -n 4',
        'Show IP Config': 'ipconfig /all',
        'Show Active Connections': 'netstat -an',
        'Show Routing Table': 'route print',
        'DNS Lookup': 'nslookup google.com',
        'Trace Route': 'tracert google.com'
    },
    'Process Management': {
        'List All Processes': 'tasklist',
        'List Services': 'net start',
        'Show Running Processes (PS)': 'Get-Process | Sort-Object CPU -Descending | Select-Object -First 10',
        'Show Memory Usage': 'systeminfo | findstr /C:"Total Physical Memory"'
    },
    'System Information': {
        'System Info': 'systeminfo',
        'Current User': 'whoami',
        'Local Users': 'net user',
        'Administrators': 'net localgroup administrators',
        'OS Version': 'ver',
        'Environment Variables': 'set'
    },
    'File Operations': {
        'List Directory': 'dir',
        'List Directory (detailed)': 'dir /a',
        'Show Current Directory': 'cd',
        'Show Disk Usage': 'wmic logicaldisk get size,freespace,caption'
    },
    'Security': {
        'Firewall Status': 'netsh advfirewall show allprofiles',
        'Show Firewall Rules': 'netsh advfirewall firewall show rule name=all',
        'Check Windows Defender': 'Get-MpComputerStatus'
    }
}


def create_terminal_session(max_history: int = 100) -> TerminalSession:
    """Create and initialize a terminal session"""
    return TerminalSession(max_history)
