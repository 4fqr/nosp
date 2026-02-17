"""
NOSP AI Module
Handles Ollama integration with automatic model management and threat analysis.
"""

import logging
from typing import Dict, Optional
import time
from .errors import report_exception, graceful, Result

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError as e:
    OLLAMA_AVAILABLE = False
    logger.warning("⚠ Ollama package not installed. AI features will be limited.")
    report_exception(e, context="ai_engine_import")


class NOSPAIEngine :
    """
    AI engine for security threat analysis using local Ollama models.
    Automatically manages model availability and provides fallback behavior.
    """

    def __init__ (self ,model_name :str ="llama3"):
        """
        Initialize AI engine with automatic model management.
        
        Args:
            model_name: Name of the Ollama model to use (default: llama3)
        """
        self .model_name =model_name
        self .model_ready =False
        self .ollama_running =False

        if not OLLAMA_AVAILABLE :
            logger .error ("✗ Ollama package not available. Install with: pip install ollama")
            return

        self ._check_ollama_service ()
        if self .ollama_running :
            self ._ensure_model_available ()

    from .stability import retry

    @retry(max_attempts=3, initial_delay=0.2, backoff=2.0, exceptions=(Exception,))
    def _check_ollama_service (self )->bool :
        """Check if Ollama service is running."""
        try:
            ollama.list()
            self.ollama_running = True
            logger.info("✓ Ollama service is running")
            return True
        except Exception as e:
            logger.error(f"✗ Ollama service not accessible: {e}")
            logger.error("  Please ensure Ollama is installed and running.")
            logger.error("  Download from: https://ollama.ai")
            report_exception(e, context="ai_engine_check_service")
            self.ollama_running = False
            return False

    from .stability import retry

    @retry(max_attempts=3, initial_delay=0.5, backoff=2.0, exceptions=(Exception,))
    def _ensure_model_available (self )->bool :
        """
        Ensure the required model is available locally.
        If not, automatically pull it.
        """
        try :
            models =ollama .list ()
            model_names =[model ['name']for model in models .get ('models',[])]

            model_found =any (self .model_name in name for name in model_names )

            if model_found :
                logger .info (f"✓ Model '{self .model_name }' is available")
                self .model_ready =True
                return True

            logger .info (f"⟳ Model '{self .model_name }' not found. Pulling from Ollama...")
            logger .info ("  This may take a few minutes depending on your connection...")

            try :
                ollama .pull (self .model_name )
                logger .info (f"✓ Model '{self .model_name }' pulled successfully")
                self .model_ready =True
                return True
            except Exception as pull_error:
                logger.error(f"✗ Failed to pull model: {pull_error}")
                logger.error("  Please run manually: ollama pull mistral-small")
                report_exception(pull_error, context="ai_engine_pull_model")
                return False

        except Exception as e:
            logger.error(f"✗ Failed to check model availability: {e}")
            report_exception(e, context="ai_engine_ensure_model")
            return False

    def analyze_process (self ,event :Dict )->Optional [str ]:
        """
        Analyze a process event for potential security threats.
        
        Args:
            event: Dictionary containing process event data
            
        Returns:
            AI-generated analysis string or None if analysis failed
        """
        if not self .model_ready :
            return "⚠ AI analysis unavailable: Model not ready"

        try :
            prompt =self ._build_analysis_prompt (event )

            response =ollama .chat (
            model =self .model_name ,
            messages =[{
            'role':'system',
            'content':'You are a cybersecurity expert analyzing Windows process events for potential threats. Provide concise, actionable analysis.'
            },{
            'role':'user',
            'content':prompt
            }]
            )

            analysis =response ['message']['content']

            mitre_info =self ._parse_mitre_attack (analysis )

            logger .info (f"✓ AI analysis completed for process: {event .get ('image','unknown')}")
            return analysis

        except Exception as e:
            logger.error(f"✗ AI analysis failed: {e}")
            report_exception(e, context="ai_engine_analyze_process")
            return f"⚠ Analysis error: {str(e)}"

    @graceful()
    def analyze_process_safe(self, event: Dict) -> Result:
        return self.analyze_process(event)

    def _parse_mitre_attack (self ,analysis_text :str )->Dict :
        """
        Parse MITRE ATT&CK information from analysis.
        
        Args:
            analysis_text: AI analysis text
            
        Returns:
            Dictionary with tactic, technique, and threat level
        """
        import re

        result ={
        'tactic':None ,
        'technique':None ,
        'threat_level':None
        }

        tactic_match =re .search (r'MITRE_TACTIC:\s*([^\n]+)',analysis_text ,re .IGNORECASE )
        if tactic_match :
            result ['tactic']=tactic_match .group (1 ).strip ()

        technique_match =re .search (r'MITRE_TECHNIQUE:\s*([^\n]+)',analysis_text ,re .IGNORECASE )
        if technique_match :
            result ['technique']=technique_match .group (1 ).strip ()

        threat_match =re .search (r'THREAT_LEVEL:\s*([^\n]+)',analysis_text ,re .IGNORECASE )
        if threat_match :
            result ['threat_level']=threat_match .group (1 ).strip ()

        return result

    def _build_analysis_prompt (self ,event :Dict )->str :
        """Build a detailed prompt for AI analysis."""
        return f"""Analyze this Windows process for security threats:

**Process Information:**
- Executable: {event .get ('image','N/A')}
- Command Line: {event .get ('command_line','N/A')}
- Process ID: {event .get ('process_id','N/A')}
- User: {event .get ('user','N/A')}

**Parent Process:**
- Parent Executable: {event .get ('parent_image','N/A')}
- Parent Command Line: {event .get ('parent_command_line','N/A')}

**File Hashes:**
{self ._format_hashes (event .get ('hashes',{}))}

Provide a STRUCTURED security assessment in this EXACT format:

THREAT_LEVEL: [Low|Medium|High|Critical]
MITRE_TACTIC: [e.g., Execution, Persistence, Defense Evasion, etc.]
MITRE_TECHNIQUE: [e.g., T1059.001 - PowerShell, T1055 - Process Injection]
INDICATORS: [List 2-3 specific suspicious indicators]
RECOMMENDATION: [Brief recommended action]
EXPLANATION: [2-3 sentence explanation]

Be specific about MITRE ATT&CK techniques. Use exact technique IDs."""

    def _format_hashes (self ,hashes :Dict )->str :
        """Format file hashes for display."""
        if not hashes :
            return "- No hashes available"
        return "\n".join ([f"- {k }: {v [:16 ]}..."for k ,v in hashes .items ()])

    def batch_analyze (self ,events :list )->Dict [int ,str ]:
        """
        Analyze multiple events efficiently.
        
        Args:
            events: List of event dictionaries
            
        Returns:
            Dictionary mapping event IDs to analysis results
        """
        results ={}

        for event in events :
            event_id =event .get ('id')
            if event_id :
                analysis =self .analyze_process (event )
                if analysis :
                    results [event_id ]=analysis
                time .sleep (0.5 )

        return results

    def get_status (self )->Dict [str ,any ]:
        """Get current AI engine status."""
        return {
        'ollama_installed':OLLAMA_AVAILABLE ,
        'ollama_running':self .ollama_running ,
        'model_ready':self .model_ready ,
        'model_name':self .model_name
        }
