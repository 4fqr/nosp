"""
NOSP vAPEX - System Hardening Module
Automatic Windows security auditing and hardening via PowerShell
"""

import subprocess 
import logging 
from typing import Dict ,List ,Tuple ,Optional 
from dataclasses import dataclass 
import re 

logger =logging .getLogger (__name__ )


@dataclass 
class SecurityCheck :
    """Represents a single security check"""
    name :str 
    description :str 
    check_command :str 
    fix_command :str 
    expected_value :str 
    severity :str 


class SystemHardener :
    """
    Windows system security auditor and hardener
    
    Features:
    - Audit Windows Defender status
    - Check Windows Firewall configuration
    - Verify Guest account is disabled
    - Verify UAC is enabled
    - Check automatic updates
    - One-click hardening (with user confirmation)
    """

    def __init__ (self ):
        self .checks :List [SecurityCheck ]=[]
        self .audit_results :Dict [str ,Dict ]={}

        self ._initialize_checks ()

    def _initialize_checks (self ):
        """Define all security checks"""

        self .checks =[
        SecurityCheck (
        name ="Windows Defender Real-Time Protection",
        description ="Ensures real-time malware scanning is active",
        check_command ="Get-MpPreference | Select-Object -ExpandProperty DisableRealtimeMonitoring",
        fix_command ="Set-MpPreference -DisableRealtimeMonitoring $false",
        expected_value ="False",
        severity ="critical"
        ),
        SecurityCheck (
        name ="Windows Defender Cloud Protection",
        description ="Enables cloud-based threat intelligence",
        check_command ="Get-MpPreference | Select-Object -ExpandProperty MAPSReporting",
        fix_command ="Set-MpPreference -MAPSReporting Advanced",
        expected_value ="2",
        severity ="high"
        ),
        SecurityCheck (
        name ="Windows Firewall (Domain Profile)",
        description ="Ensures firewall is active on domain networks",
        check_command ="(Get-NetFirewallProfile -Name Domain).Enabled",
        fix_command ="Set-NetFirewallProfile -Name Domain -Enabled True",
        expected_value ="True",
        severity ="critical"
        ),
        SecurityCheck (
        name ="Windows Firewall (Private Profile)",
        description ="Ensures firewall is active on private networks",
        check_command ="(Get-NetFirewallProfile -Name Private).Enabled",
        fix_command ="Set-NetFirewallProfile -Name Private -Enabled True",
        expected_value ="True",
        severity ="critical"
        ),
        SecurityCheck (
        name ="Windows Firewall (Public Profile)",
        description ="Ensures firewall is active on public networks",
        check_command ="(Get-NetFirewallProfile -Name Public).Enabled",
        fix_command ="Set-NetFirewallProfile -Name Public -Enabled True",
        expected_value ="True",
        severity ="critical"
        ),
        SecurityCheck (
        name ="Guest Account Status",
        description ="Ensures Guest account is disabled",
        check_command ="(Get-LocalUser -Name Guest).Enabled",
        fix_command ="Disable-LocalUser -Name Guest",
        expected_value ="False",
        severity ="high"
        ),
        SecurityCheck (
        name ="UAC (User Account Control)",
        description ="Ensures UAC prompts are enabled",
        check_command ="(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').EnableLUA",
        fix_command ="Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1",
        expected_value ="1",
        severity ="critical"
        ),
        SecurityCheck (
        name ="Automatic Updates",
        description ="Ensures Windows Update automatic installation is enabled",
        check_command ="(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -ErrorAction SilentlyContinue).AUOptions",
        fix_command ="# Note: Managed via Group Policy or Settings app",
        expected_value ="4",
        severity ="medium"
        ),
        SecurityCheck (
        name ="SMBv1 Protocol",
        description ="Ensures vulnerable SMBv1 is disabled",
        check_command ="(Get-SmbServerConfiguration).EnableSMB1Protocol",
        fix_command ="Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
        expected_value ="False",
        severity ="high"
        ),
        SecurityCheck (
        name ="Remote Desktop",
        description ="Checks if RDP is enabled (should be disabled unless needed)",
        check_command ="(Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections",
        fix_command ="Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1",
        expected_value ="1",
        severity ="medium"
        )
        ]

    def run_powershell_command (self ,command :str )->Tuple [bool ,str ,str ]:
        """
        Execute a PowerShell command safely
        
        Returns:
            Tuple of (success, stdout, stderr)
        """
        try :
            result =subprocess .run (
            ["powershell","-ExecutionPolicy","Bypass","-Command",command ],
            capture_output =True ,
            text =True ,
            timeout =10 
            )

            success =result .returncode ==0 
            stdout =result .stdout .strip ()
            stderr =result .stderr .strip ()

            return success ,stdout ,stderr 

        except subprocess .TimeoutExpired :
            logger .error (f"PowerShell command timed out: {command }")
            return False ,"","Command timed out"
        except Exception as e :
            logger .error (f"PowerShell execution failed: {e }")
            return False ,"",str (e )

    def audit_system (self )->Dict [str ,Dict ]:
        """
        Audit all security settings
        
        Returns:
            Dictionary of check results
        """
        logger .info ("Starting system security audit...")
        self .audit_results .clear ()

        for check in self .checks :
            logger .info (f"Checking: {check .name }")

            success ,stdout ,stderr =self .run_powershell_command (check .check_command )

            if success :
                actual_value =stdout 
                is_compliant =self ._compare_values (actual_value ,check .expected_value )

                self .audit_results [check .name ]={
                'description':check .description ,
                'severity':check .severity ,
                'compliant':is_compliant ,
                'expected':check .expected_value ,
                'actual':actual_value ,
                'error':None 
                }
            else :
                self .audit_results [check .name ]={
                'description':check .description ,
                'severity':check .severity ,
                'compliant':False ,
                'expected':check .expected_value ,
                'actual':None ,
                'error':stderr or "Command failed"
                }

        logger .info (f"Audit complete: {len (self .audit_results )} checks performed")
        return self .audit_results 

    def _compare_values (self ,actual :str ,expected :str )->bool :
        """Compare actual value with expected (flexible comparison)"""
        actual_clean =actual .strip ().lower ()
        expected_clean =expected .strip ().lower ()

        if actual_clean ==expected_clean :
            return True 

        try :
            return int (actual_clean )==int (expected_clean )
        except :
            pass 

        return False 

    def harden_system (self ,checks_to_fix :Optional [List [str ]]=None )->Dict [str ,bool ]:
        """
        Apply security hardening fixes
        
        Args:
            checks_to_fix: List of check names to fix (None = fix all non-compliant)
        
        Returns:
            Dictionary of fix results (check_name -> success)
        """
        logger .info ("Starting system hardening...")
        results ={}

        if checks_to_fix is None :
            checks_to_fix =[
            name for name ,result in self .audit_results .items ()
            if not result ['compliant']and result ['error']is None 
            ]

        for check in self .checks :
            if check .name not in checks_to_fix :
                continue 

            logger .info (f"Hardening: {check .name }")

            if not check .fix_command or check .fix_command .startswith ("#"):
                logger .warning (f"No automated fix available for: {check .name }")
                results [check .name ]=False 
                continue 

            success ,stdout ,stderr =self .run_powershell_command (check .fix_command )
            results [check .name ]=success 

            if success :
                logger .info (f"✓ Fixed: {check .name }")
            else :
                logger .error (f"✗ Failed to fix: {check .name } - {stderr }")

        return results 

    def get_summary (self )->Dict [str ,int ]:
        """Get audit summary statistics"""
        if not self .audit_results :
            return {
            'total':0 ,
            'compliant':0 ,
            'non_compliant':0 ,
            'errors':0 ,
            'critical':0 ,
            'high':0 ,
            'medium':0 ,
            'low':0 
            }

        summary ={
        'total':len (self .audit_results ),
        'compliant':0 ,
        'non_compliant':0 ,
        'errors':0 ,
        'critical':0 ,
        'high':0 ,
        'medium':0 ,
        'low':0 
        }

        for result in self .audit_results .values ():
            if result ['error']:
                summary ['errors']+=1 
            elif result ['compliant']:
                summary ['compliant']+=1 
            else :
                summary ['non_compliant']+=1 

            severity =result ['severity']
            if severity in summary :
                if not result ['compliant']and not result ['error']:
                    summary [severity ]+=1 

        return summary 

    def get_compliance_score (self )->float :
        """Calculate overall compliance percentage"""
        if not self .audit_results :
            return 0.0 

        compliant =sum (1 for r in self .audit_results .values ()if r ['compliant'])
        total =len (self .audit_results )

        return (compliant /total )*100 if total >0 else 0.0 

    def generate_report (self )->str :
        """Generate a text report of audit results"""
        if not self .audit_results :
            return "No audit results available. Run audit_system() first."

        report =[]
        report .append ("="*80 )
        report .append ("NOSP SYSTEM SECURITY AUDIT REPORT")
        report .append ("="*80 )
        report .append ("")

        summary =self .get_summary ()
        compliance =self .get_compliance_score ()

        report .append (f"Overall Compliance Score: {compliance :.1f}%")
        report .append (f"Total Checks: {summary ['total']}")
        report .append (f"Compliant: {summary ['compliant']}")
        report .append (f"Non-Compliant: {summary ['non_compliant']}")
        report .append (f"Errors: {summary ['errors']}")
        report .append ("")
        report .append (f"Issues by Severity:")
        report .append (f"  Critical: {summary ['critical']}")
        report .append (f"  High: {summary ['high']}")
        report .append (f"  Medium: {summary ['medium']}")
        report .append (f"  Low: {summary ['low']}")
        report .append ("")
        report .append ("-"*80 )
        report .append ("DETAILED RESULTS")
        report .append ("-"*80 )
        report .append ("")

        for name ,result in self .audit_results .items ():
            status ="✓ PASS"if result ['compliant']else "✗ FAIL"
            if result ['error']:
                status ="⚠ ERROR"

            report .append (f"[{result ['severity'].upper ()}] {name }")
            report .append (f"  Status: {status }")
            report .append (f"  Description: {result ['description']}")

            if result ['error']:
                report .append (f"  Error: {result ['error']}")
            else :
                report .append (f"  Expected: {result ['expected']}")
                report .append (f"  Actual: {result ['actual']}")

            report .append ("")

        return "\n".join (report )


def create_system_hardener ()->SystemHardener :
    """Create and initialize a system hardener instance"""
    return SystemHardener ()
