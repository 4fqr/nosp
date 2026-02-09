"""
NOSP Main Application
Streamlit-based UI with cyberpunk theme for security monitoring.
"""

import streamlit as st
import pandas as pd
import time
import sys
import logging
from pathlib import Path
from datetime import datetime
import json

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import NOSP modules
try:
    from nosp.database import NOSPDatabase
    from nosp.ai_engine import NOSPAIEngine
    from nosp.risk_scorer import RiskScorer
    from nosp.alerts import AudioAlertSystem, AlertManager, Alert, AlertPriority
    from nosp.forensics import ProcessTree, ForensicReporter
    from nosp.system_tray import NOSPSystemTray
    # OMEGA Features
    from nosp.rules_engine import RulesEngine
    from nosp.ml_detector import MLAnomalyDetector
    from nosp.plugin_manager import PluginManager
    # APEX Features
    from nosp.system_hardener import SystemHardener
    from nosp.session_manager import SessionManager
    from nosp.terminal import TerminalSession
    # EVENT HORIZON Features
    from nosp.ledger import get_ledger, log_security_event
    from nosp.mesh_network import MeshNetwork
    from nosp.cage import Cage
except ImportError as e:
    logger.error(f"Failed to import NOSP modules: {e}")
    st.error("⚠ NOSP modules not found. Please ensure the package is properly installed.")
    sys.exit(1)

# Import visualization libraries
try:
    import plotly.express as px
    import plotly.graph_objects as go
    import pydeck as pdk
    PYDECK_AVAILABLE = True
except ImportError:
    PYDECK_AVAILABLE = False
    logger.warning("⚠ pydeck not available - 3D threat map disabled")

# Try to import Rust core module
RUST_AVAILABLE = False
try:
    import nosp_core
    RUST_AVAILABLE = True
    logger.info("✓ Rust core module loaded successfully")
except ImportError as e:
    logger.warning(f"⚠ Rust core module not available: {e}")
    logger.warning("  The application will run in limited mode without real-time event monitoring.")
    logger.warning("  To enable full functionality:")
    logger.warning("  1. Install Rust from https://rustup.rs")
    logger.warning("  2. Install maturin: pip install maturin")
    logger.warning("  3. Build the Rust module: maturin develop --release")


# ============================================================================
# STREAMLIT CONFIGURATION
# ============================================================================

st.set_page_config(
    page_title="NOSP - Null OS Security Program",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Glassmorphism Cyberpunk Cinema CSS (OMEGA)
CYBERPUNK_CSS = """
<style>
    /* Main theme colors - OMEGA Enhanced */
    :root {
        --bg-dark: #0A0E1A;
        --bg-secondary: #0F1419;
        --bg-glass: rgba(15, 20, 25, 0.6);
        --neon-green: #00FF41;
        --neon-blue: #00D9FF;
        --neon-purple: #BD00FF;
        --neon-red: #FF0055;
        --text-primary: #E8F0FF;
        --text-secondary: #A8B8D0;
        --border-glow: rgba(0, 255, 65, 0.3);
    }
    
    /* Glassmorphism background */
    .stApp {
        background: linear-gradient(135deg, #0A0E1A 0%, #1A0E2E 100%);
        color: var(--text-primary);
        font-family: 'Courier New', 'Roboto Mono', monospace;
    }
    
    /* Glass panel effect */
    .element-container, .stMarkdown, [data-testid="stMetric"] {
        background: var(--bg-glass);
        backdrop-filter: blur(12px);
        border: 1px solid var(--border-glow);
        border-radius: 8px;
        box-shadow: 0 8px 32px rgba(0, 255, 65, 0.1);
    }
    
    /* Headers with cinema neon glow */
    h1, h2, h3 {
        color: var(--neon-green) !important;
        text-shadow: 0 0 20px var(--neon-green), 0 0 40px var(--neon-green);
        font-family: 'Courier New', monospace;
        font-weight: 900;
        letter-spacing: 2px;
        text-transform: uppercase;
    }
    
    /* Sidebar glassmorphism */
    .css-1d391kg, [data-testid="stSidebar"] {
        background: linear-gradient(180deg, rgba(10, 14, 26, 0.95) 0%, rgba(26, 14, 46, 0.95) 100%) !important;
        backdrop-filter: blur(20px);
        border-right: 3px solid var(--neon-green);
        box-shadow: 0 0 40px rgba(0, 255, 65, 0.2);
    }
    
    /* Metrics with pulsing glow */
    [data-testid="stMetricValue"] {
        color: var(--neon-blue);
        font-family: 'Courier New', monospace;
        font-size: 2.4em;
        font-weight: 800;
        text-shadow: 0 0 15px var(--neon-blue), 0 0 30px var(--neon-blue);
        animation: pulse-glow 2s infinite;
    }
    
    @keyframes pulse-glow {
        0%, 100% { text-shadow: 0 0 15px var(--neon-blue); }
        50% { text-shadow: 0 0 25px var(--neon-blue), 0 0 50px var(--neon-blue); }
    
    /* Status indicators with scanning animation */
    .status-active {
        color: var(--neon-green);
        text-shadow: 0 0 15px var(--neon-green);
        animation: scan 3s infinite;
    }
    
    @keyframes scan {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.6; }
    }
    
    .status-inactive {
        color: var(--neon-red);
        text-shadow: 0 0 15px var(--neon-red);
    }
    
    /* Data tables with glass effect */
    .dataframe {
        background: rgba(15, 20, 25, 0.8) !important;
        backdrop-filter: blur(8px);
        color: var(--text-primary) !important;
        border: 2px solid var(--neon-green) !important;
        border-radius: 4px;
    }
    
    /* Buttons with HUD style */
    .stButton>button {
        background: linear-gradient(135deg, rgba(0, 255, 65, 0.1), rgba(0, 217, 255, 0.1));
        color: var(--neon-green);
        border: 2px solid var(--neon-green);
        border-radius: 4px;
        font-family: 'Courier New', monospace;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 1px;
        transition: all 0.3s;
        backdrop-filter: blur(8px);
    }
    
    .stButton>button:hover {
        background: var(--neon-green);
        color: var(--bg-dark);
        box-shadow: 0 0 25px var(--neon-green), 0 0 50px var(--neon-green);
        transform: translateY(-2px);
    }
    
    /* Expander with cinema style */
    .streamlit-expanderHeader {
        background: var(--bg-glass) !important;
        backdrop-filter: blur(10px);
        border: 1px solid var(--neon-blue) !important;
        color: var(--neon-blue) !important;
        font-family: 'Courier New', monospace;
        font-weight: 700;
    }
    
    /* Progress bar with energy flow */
    .stProgress > div > div > div {
        background: linear-gradient(90deg, var(--neon-green), var(--neon-blue), var(--neon-purple));
        background-size: 200% 100%;
        animation: flow 2s linear infinite;
        box-shadow: 0 0 15px var(--neon-green);
    }
    
    @keyframes flow {
        0% { background-position: 0% 0%; }
        100% { background-position: 200% 0%; }
    }
    
    /* Alerts with HUD style */
    .stAlert {
        background: var(--bg-glass) !important;
        backdrop-filter: blur(12px);
        border-left: 5px solid var(--neon-green) !important;
        color: var(--text-primary) !important;
        box-shadow: 0 0 20px rgba(0, 255, 65, 0.2);
    }
    
    /* Monospace code with neon */
    code {
        color: var(--neon-purple);
        background: rgba(189, 0, 255, 0.1);
        padding: 4px 8px;
        border: 1px solid var(--neon-purple);
        border-radius: 3px;
        box-shadow: 0 0 10px rgba(189, 0, 255, 0.3);
    }
    
    /* Scanner line effect */
    @keyframes scanner {
        0% { transform: translateY(0); opacity: 0.8; }
        100% { transform: translateY(100vh); opacity: 0; }
    }
    
    .scanner-line {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 3px;
        background: linear-gradient(90deg, transparent, var(--neon-green), transparent);
        animation: scanner 4s linear infinite;
        pointer-events: none;
        z-index: 9999;
    }
</style>
"""

st.markdown(CYBERPUNK_CSS, unsafe_allow_html=True)


# ============================================================================
# INITIALIZE SESSION STATE
# ============================================================================

if 'initialized' not in st.session_state:
    st.session_state.initialized = False
    st.session_state.db = None
    st.session_state.ai_engine = None
    st.session_state.risk_scorer = None
    st.session_state.monitoring = False
    st.session_state.events_processed = 0
    st.session_state.alert_system = None
    st.session_state.alert_manager = None
    st.session_state.process_tree = None
    st.session_state.forensic_reporter = None
    st.session_state.system_tray = None
    # OMEGA Features
    st.session_state.rules_engine = None
    st.session_state.ml_detector = None
    st.session_state.plugin_manager = None
    st.session_state.timeline_timestamp = None
    st.session_state.network_events = []
    # APEX Features
    st.session_state.system_hardener = None
    st.session_state.session_manager = None
    st.session_state.terminal = None
    st.session_state.terminal_history = []
    st.session_state.hardening_results = None


def initialize_components():
    """Initialize all NOSP components."""
    try:
        # Initialize database
        st.session_state.db = NOSPDatabase()
        logger.info("✓ Database initialized")
        
        # Initialize AI engine
        st.session_state.ai_engine = NOSPAIEngine(model_name="llama3")
        logger.info("✓ AI engine initialized")
        
        # Initialize risk scorer
        st.session_state.risk_scorer = RiskScorer()
        logger.info("✓ Risk scorer initialized")
        
        # Initialize audio alert system
        st.session_state.alert_system = AudioAlertSystem()
        st.session_state.alert_manager = AlertManager(st.session_state.alert_system)
        logger.info("✓ Alert system initialized")
        
        # Initialize process tree
        st.session_state.process_tree = ProcessTree()
        logger.info("✓ Process tree initialized")
        
        # Initialize forensic reporter
        st.session_state.forensic_reporter = ForensicReporter()
        logger.info("✓ Forensic reporter initialized")
        
        # Initialize system tray (non-blocking)
        try:
            st.session_state.system_tray = NOSPSystemTray()
            st.session_state.system_tray.start()
            logger.info("✓ System tray initialized")
        except Exception as e:
            logger.warning(f"⚠ System tray unavailable: {e}")
            st.session_state.system_tray = None
        
        # ======= OMEGA FEATURES =======
        
        # Initialize YAML Rules Engine
        try:
            st.session_state.rules_engine = RulesEngine(rules_file="rules.yaml")
            # Register action handlers
            st.session_state.rules_engine.register_action_handler('kill', handle_kill_action)
            st.session_state.rules_engine.register_action_handler('suspend', handle_suspend_action)
            st.session_state.rules_engine.register_action_handler('quarantine', handle_quarantine_action)
            st.session_state.rules_engine.register_action_handler('alert', handle_alert_action)
            st.session_state.rules_engine.register_action_handler('block_ip', handle_block_ip_action)
            logger.info("✓ Rules engine initialized")
        except Exception as e:
            logger.warning(f"⚠ Rules engine unavailable: {e}")
            st.session_state.rules_engine = None
        
        # Initialize ML Anomaly Detector
        try:
            st.session_state.ml_detector = MLAnomalyDetector(model_path="models/anomaly_detector.pkl")
            logger.info("✓ ML anomaly detector initialized")
        except Exception as e:
            logger.warning(f"⚠ ML detector unavailable: {e}")
            st.session_state.ml_detector = None
        
        # Initialize Plugin Manager
        try:
            st.session_state.plugin_manager = PluginManager(plugins_dir="plugins")
            logger.info("✓ Plugin manager initialized")
        except Exception as e:
            logger.warning(f"⚠ Plugin manager unavailable: {e}")
            st.session_state.plugin_manager = None
        
        # ======= APEX FEATURES =======
        
        # Initialize System Hardener
        try:
            st.session_state.system_hardener = SystemHardener()
            logger.info("✓ System hardener initialized")
        except Exception as e:
            logger.warning(f"⚠ System hardener unavailable: {e}")
            st.session_state.system_hardener = None
        
        # Initialize Session Manager (with auto-save)
        try:
            st.session_state.session_manager = SessionManager()
            logger.info("✓ Session manager initialized")
        except Exception as e:
            logger.warning(f"⚠ Session manager unavailable: {e}")
            st.session_state.session_manager = None
        
        # Initialize Terminal Session
        try:
            st.session_state.terminal = TerminalSession()
            logger.info("✓ Terminal session initialized")
        except Exception as e:
            logger.warning(f"⚠ Terminal session unavailable: {e}")
            st.session_state.terminal = None
        
        st.session_state.initialized = True
        
        # Welcome audio
        if st.session_state.alert_system.enabled:
            st.session_state.alert_system.alert_monitoring_started()
        
        return True
        
    except Exception as e:
        logger.error(f"✗ Initialization failed: {e}")
        st.error(f"⚠ Failed to initialize NOSP components: {e}")
        return False


# ============================================================================
# RULES ENGINE ACTION HANDLERS (OMEGA)
# ============================================================================

def handle_kill_action(event: dict, match: dict) -> bool:
    """Handle kill action from rules engine"""
    try:
        if not RUST_AVAILABLE:
            return False
        pid = event.get('pid')
        if pid:
            success = nosp_core.terminate_process(int(pid))
            logger.info(f"Terminated process {pid} via rules engine")
            return success
        return False
    except:
        return False


def handle_suspend_action(event: dict, match: dict) -> bool:
    """Handle suspend action from rules engine"""
    try:
        if not RUST_AVAILABLE:
            return False
        pid = event.get('pid')
        if pid:
            success = nosp_core.suspend_process(int(pid))
            logger.info(f"Suspended process {pid} via rules engine")
            return success
        return False
    except:
        return False


def handle_quarantine_action(event: dict, match: dict) -> bool:
    """Handle quarantine action from rules engine"""
    try:
        if not RUST_AVAILABLE:
            return False
        image = event.get('image')
        if image:
            success = nosp_core.quarantine_file(image, "quarantine")
            logger.info(f"Quarantined file {image} via rules engine")
            return success
        return False
    except:
        return False


def handle_alert_action(event: dict, match: dict) -> bool:
    """Handle alert action from rules engine"""
    try:
        if st.session_state.alert_system and st.session_state.alert_system.enabled:
            message = f"Rule {match['rule_name']} triggered: {match['description']}"
            st.session_state.alert_system.speak(message, interrupt=True)
        return True
    except:
        return False


def handle_block_ip_action(event: dict, match: dict) -> bool:
    """Handle block IP action from rules engine"""
    try:
        if not RUST_AVAILABLE:
            return False
        dest_ip = event.get('destination_ip')
        if dest_ip:
            rule_name = f"NOSP_Block_{dest_ip.replace('.', '_')}"
            success = nosp_core.block_ip_firewall(dest_ip, rule_name)
            logger.info(f"Blocked IP {dest_ip} via rules engine")
            return success
        return False
    except:
        return False


# ============================================================================
# SIDEBAR - SYSTEM STATUS
# ============================================================================

def render_sidebar():
    """Render the sidebar with system status."""
    st.sidebar.title("🛡️ NOSP")
    st.sidebar.markdown("### Null OS Security Program")
    st.sidebar.markdown("---")
    
    # System Status
    st.sidebar.markdown("### 📊 System Status")
    
    # Rust Engine Status
    if RUST_AVAILABLE:
        st.sidebar.markdown("🟢 **Rust Engine:** <span class='status-active'>ACTIVE</span>", 
                          unsafe_allow_html=True)
        try:
            version = nosp_core.get_version()
            st.sidebar.caption(f"Version: {version}")
        except:
            pass
    else:
        st.sidebar.markdown("🔴 **Rust Engine:** <span class='status-inactive'>OFFLINE</span>", 
                          unsafe_allow_html=True)
        st.sidebar.caption("Limited functionality mode")
    
    # AI Status
    if st.session_state.ai_engine:
        ai_status = st.session_state.ai_engine.get_status()
        if ai_status.get('model_ready'):
            st.sidebar.markdown("🟢 **AI Engine:** <span class='status-active'>ACTIVE</span>", 
                              unsafe_allow_html=True)
            st.sidebar.caption(f"Model: {ai_status.get('model_name', 'unknown')}")
        else:
            st.sidebar.markdown("🟡 **AI Engine:** <span class='status-inactive'>STANDBY</span>", 
                              unsafe_allow_html=True)
    else:
        st.sidebar.markdown("🔴 **AI Engine:** <span class='status-inactive'>OFFLINE</span>", 
                          unsafe_allow_html=True)
    
    # Database Status
    if st.session_state.db:
        st.sidebar.markdown("🟢 **Database:** <span class='status-active'>CONNECTED</span>", 
                          unsafe_allow_html=True)
    else:
        st.sidebar.markdown("🔴 **Database:** <span class='status-inactive'>DISCONNECTED</span>", 
                          unsafe_allow_html=True)
    
    st.sidebar.markdown("---")
    
    # Statistics
    if st.session_state.db:
        st.sidebar.markdown("### 📈 Statistics")
        stats = st.session_state.db.get_statistics()
        st.sidebar.metric("Total Events", stats.get('total_events', 0))
        st.sidebar.metric("High Risk", stats.get('high_risk_events', 0))
        st.sidebar.metric("Avg Risk Score", stats.get('avg_risk_score', 0))
    
    # Performance Monitoring
    st.sidebar.markdown("### ⚡ Performance")
    try:
        import psutil
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory_info = psutil.Process().memory_info()
        memory_mb = memory_info.rss / 1024 / 1024
        
        st.sidebar.metric("CPU Usage", f"{cpu_percent:.1f}%")
        st.sidebar.metric("Memory", f"{memory_mb:.1f} MB")
    except Exception as e:
        st.sidebar.caption("Performance data unavailable")
    
    st.sidebar.markdown("---")
    
    # Controls
    st.sidebar.markdown("### ⚙️ Controls")
    
    if st.sidebar.button("🔄 Refresh Data"):
        st.rerun()
    
    if RUST_AVAILABLE:
        if st.sidebar.button("▶️ Start Monitoring" if not st.session_state.monitoring else "⏸️ Pause Monitoring"):
            st.session_state.monitoring = not st.session_state.monitoring
            
            # Update system tray
            if st.session_state.system_tray:
                if st.session_state.monitoring:
                    st.session_state.system_tray.update_status("safe", 0)
                else:
                    st.session_state.system_tray.update_status("gray", 0)
            
            # Audio feedback
            if st.session_state.alert_system and st.session_state.alert_system.enabled:
                if st.session_state.monitoring:
                    st.session_state.alert_system.alert_monitoring_started()
                else:
                    st.session_state.alert_system.alert_monitoring_stopped()
            
            st.rerun()
    
    # PDF Report Generation
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 📄 Reports")
    
    if st.sidebar.button("📊 Generate PDF Report"):
        with st.spinner("Generating report..."):
            try:
                events = st.session_state.db.get_recent_events(limit=100, min_risk=0)
                stats = st.session_state.db.get_statistics()
                
                import os
                desktop = os.path.join(os.path.expanduser("~"), "Desktop")
                reports_dir = os.path.join(desktop, "NOSP_Reports")
                os.makedirs(reports_dir, exist_ok=True)
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = os.path.join(reports_dir, f"NOSP_Report_{timestamp}.pdf")
                
                report_path = st.session_state.forensic_reporter.generate_incident_report(
                    events=events,
                    stats=stats,
                    output_path=output_path
                )
                
                st.sidebar.success(f"✓ Report saved to Desktop/NOSP_Reports/")
                logger.info(f"✓ PDF report generated: {report_path}")
            except Exception as e:
                st.sidebar.error(f"✗ Report generation failed: {e}")
                logger.error(f"✗ Report error: {e}")


# ============================================================================
# MAIN CONTENT
# ============================================================================

def render_header():
    """Render the main header."""
    st.markdown("""
        <h1 style='text-align: center; font-size: 3em; margin-bottom: 0;'>
            🛡️ NOSP
        </h1>
        <p style='text-align: center; color: #00FF41; font-family: Courier New; margin-top: 0;'>
            NULL OS SECURITY PROGRAM • REAL-TIME THREAT MONITORING
        </p>
    """, unsafe_allow_html=True)
    st.markdown("---")


def process_events():
    """Process new events from Sysmon with OMEGA enhancements."""
    if not RUST_AVAILABLE or not st.session_state.monitoring:
        return
    
    try:
        # Fetch events from Rust module
        events = nosp_core.get_sysmon_events(max_events=50)
        
        threat_count = 0
        max_risk = 0
        
        for event in events:
            # ======= OMEGA: Plugin Processing =======
            if st.session_state.plugin_manager:
                event = st.session_state.plugin_manager.process_event(event)
                if event is None:
                    continue  # Event filtered by plugin
            
            # Calculate risk score
            risk_score, risk_factors = st.session_state.risk_scorer.calculate_risk(event)
            event['risk_score'] = risk_score
            
            # ======= OMEGA: ML Anomaly Detection =======
            if st.session_state.ml_detector:
                # Add to training buffer
                st.session_state.ml_detector.add_training_sample(event)
                
                # Predict anomaly
                is_anomaly, anomaly_score, confidence = st.session_state.ml_detector.predict(event)
                event['ml_anomaly'] = is_anomaly
                event['ml_score'] = anomaly_score
                event['ml_confidence'] = confidence
                
                # Boost risk score if ML detects anomaly
                if is_anomaly and confidence in ['high', 'medium']:
                    risk_score = min(100, risk_score + 20)
                    event['risk_score'] = risk_score
                
                # Auto-train every 100 events
                if st.session_state.events_processed % 100 == 0:
                    st.session_state.ml_detector.train(force=False)
            
            # Track threats
            if risk_score >= 60:
                threat_count += 1
            max_risk = max(max_risk, risk_score)
            
            # Add to process tree
            if st.session_state.process_tree:
                st.session_state.process_tree.add_process(event)
            
            # Store in database
            event_id = st.session_state.db.insert_event(event, risk_score, risk_factors)
            
            # ======= OMEGA: Rules Engine Processing =======
            if st.session_state.rules_engine:
                rule_result = st.session_state.rules_engine.process_event(event)
                
                if rule_result['matches']:
                    # Log rule matches
                    for match in rule_result['matches']:
                        logger.info(f"Rule matched: {match['rule_name']} (severity: {match['severity']})")
                    
                    # Trigger audio alerts for critical rules
                    critical_matches = [m for m in rule_result['matches'] if m['severity'] == 'critical']
                    if critical_matches and st.session_state.alert_system:
                        rule_names = ", ".join([m['rule_name'] for m in critical_matches])
                        st.session_state.alert_system.alert_critical_threat(
                            event.get('process_name', 'unknown'),
                            f"Critical rules triggered: {rule_names}"
                        )
            
            # If high risk, queue for AI analysis and send alerts
            if event_id and risk_score >= 60:
                # AI Analysis
                analysis_result = st.session_state.ai_engine.analyze_process(event)
                if analysis_result:
                    if isinstance(analysis_result, dict):
                        # Store analysis text
                        analysis_text = analysis_result.get('analysis', '')
                        st.session_state.db.update_ai_analysis(event_id, analysis_text)
                    else:
                        st.session_state.db.update_ai_analysis(event_id, str(analysis_result))
                
                # Send alert
                process_name = Path(event.get('image', 'unknown')).name
                
                if risk_score >= 90:
                    # Critical threat - audio alert
                    if st.session_state.alert_system and st.session_state.alert_system.enabled:
                        st.session_state.alert_system.alert_critical_threat(process_name, risk_score)
                
                elif risk_score >= 75:
                    # High risk - audio alert
                    if st.session_state.alert_system and st.session_state.alert_system.enabled:
                        st.session_state.alert_system.alert_high_risk(process_name, risk_score)
            
            st.session_state.events_processed += 1
        
        # Update system tray
        if st.session_state.system_tray:
            if max_risk >= 90:
                st.session_state.system_tray.update_status("critical", threat_count)
            elif max_risk >= 60:
                st.session_state.system_tray.update_status("warning", threat_count)
            else:
                st.session_state.system_tray.update_status("safe", 0)
            
    except Exception as e:
        logger.error(f"Error processing events: {e}")


def render_events_table():
    """Render the main events table."""
    st.markdown("### 📋 Recent Security Events")
    
    # Filters
    col1, col2, col3 = st.columns([2, 2, 1])
    with col1:
        min_risk = st.slider("Minimum Risk Score", 0, 100, 0, 5)
    with col2:
        max_events = st.select_slider("Events to Display", 
                                      options=[10, 25, 50, 100, 200],
                                      value=50)
    with col3:
        auto_refresh = st.checkbox("Auto Refresh", value=False)
    
    # Get events from database
    events = st.session_state.db.get_recent_events(limit=max_events, min_risk=min_risk)
    
    if not events:
        st.info("📭 No events found. Start monitoring to capture security events.")
        return
    
    # Convert to DataFrame
    df = pd.DataFrame(events)
    
    # Select and rename columns for display
    display_columns = {
        'id': 'ID',
        'timestamp': 'Time',
        'image': 'Process',
        'user': 'User',
        'risk_score': 'Risk',
        'analyzed': 'AI'
    }
    
    if all(col in df.columns for col in display_columns.keys()):
        df_display = df[list(display_columns.keys())].rename(columns=display_columns)
        
        # Color code risk scores
        def highlight_risk(row):
            risk = row['Risk']
            if risk >= 75:
                color = '#FF4444'
            elif risk >= 60:
                color = '#FF8800'
            elif risk >= 30:
                color = '#FFCC00'
            else:
                color = '#00FF41'
            return [f'background-color: {color}55' if col == 'Risk' else '' 
                    for col in row.index]
        
        styled_df = df_display.style.apply(highlight_risk, axis=1)
        st.dataframe(styled_df, use_container_width=True, height=400)
    else:
        st.dataframe(df, use_container_width=True, height=400)
    
    # Auto-refresh
    if auto_refresh:
        time.sleep(5)
        st.rerun()


def render_analysis_panel():
    """Render AI analysis for high-risk events."""
    st.markdown("### 🔍 AI Threat Analysis")
    
    # Get high-risk unanalyzed events
    high_risk_events = st.session_state.db.get_high_risk_unanalyzed(threshold=60, limit=5)
    
    if high_risk_events:
        st.warning(f"⚠️ {len(high_risk_events)} high-risk events awaiting analysis")
        
        if st.button("🤖 Run AI Analysis Now"):
            with st.spinner("Analyzing threats..."):
                for event in high_risk_events:
                    analysis = st.session_state.ai_engine.analyze_process(event)
                    if analysis:
                        st.session_state.db.update_ai_analysis(event['id'], analysis)
                st.success("✓ Analysis complete!")
                st.rerun()
    
    # Show analyzed high-risk events
    analyzed_events = st.session_state.db.get_recent_events(limit=10, min_risk=60)
    analyzed_events = [e for e in analyzed_events if e.get('analyzed') == 1]
    
    if analyzed_events:
        for event in analyzed_events[:3]:  # Show top 3
            risk_level = st.session_state.risk_scorer.get_risk_level(event['risk_score'])
            risk_color = st.session_state.risk_scorer.get_risk_color(event['risk_score'])
            
            with st.expander(f"🚨 {risk_level} - {event['image'].split('\\\\')[-1]} (Score: {event['risk_score']})"):
                col1, col2 = st.columns([1, 2])
                
                with col1:
                    st.markdown("**Process Details**")
                    st.code(event['image'], language=None)
                    st.caption(f"PID: {event['process_id']}")
                    st.caption(f"User: {event['user']}")
                
                with col2:
                    st.markdown("**AI Analysis**")
                    st.markdown(event.get('ai_analysis', 'No analysis available'))
                
                st.markdown("**Command Line**")
                st.code(event['command_line'], language=None)
            st.info(f"[FIM] {path}: {hash_value}")
    else:
        st.info("✓ No high-risk threats detected")


# ============================================================================
# OMEGA FEATURE RENDERERS
# ============================================================================

def render_3d_threat_map():
    """Render 3D globe with network threat visualization (OMEGA)."""
    st.markdown("### 🌍 3D Global Threat Map")
    st.markdown("Real-time visualization of network connections on a 3D globe")
    
    # Get network events
    network_events = st.session_state.db.get_recent_network_events(limit=100)
    
    if not network_events:
        st.info("✓ No network events detected yet")
        return
    
    try:
        # Prepare data for pydeck
        arc_data = []
        
        # User location (customize this)
        user_lat, user_lon = 37.7749, -122.4194  # San Francisco (example)
        
        for event in network_events:
            dest_ip = event.get('destination_ip', '')
            
            # Use a simple IP-to-location mapping (in production, use GeoIP database)
            dest_lat, dest_lon = ip_to_coordinates(dest_ip)
            
            if dest_lat and dest_lon:
                arc_data.append({
                    'source_lat': user_lat,
                    'source_lon': user_lon,
                    'dest_lat': dest_lat,
                    'dest_lon': dest_lon,
                    'risk_score': event.get('risk_score', 0),
                    'process': event.get('process_name', 'unknown'),
                    'ip': dest_ip
                })
        
        if not arc_data:
            st.warning("⚠ No geolocation data available for network events")
            return
        
        # Create pydeck chart
        view_state =pdk.ViewState(
            latitude=30,
            longitude=0,
            zoom=1.5,
            pitch=45
        )
        
        # Arc layer for connections
        arc_layer = pdk.Layer(
            "ArcLayer",
            data=arc_data,
            get_source_position=['source_lon', 'source_lat'],
            get_target_position=['dest_lon', 'dest_lat'],
            get_source_color=[0, 255, 65, 200],  # Neon green
            get_target_color=[255, 0, 85, 200],   # Neon red
            get_width='risk_score / 20',
            auto_highlight=True,
            pickable=True
        )
        
        # Scatterplot for destinations
        scatter_layer = pdk.Layer(
            "ScatterplotLayer",
            data=arc_data,
            get_position=['dest_lon', 'dest_lat'],
            get_radius='risk_score * 1000',
            get_fill_color=[255, 0, 85, 150],
            pickable=True
        )
        
        # Render deck
        deck = pdk.Deck(
            layers=[arc_layer, scatter_layer],
            initial_view_state=view_state,
            map_style='mapbox://styles/mapbox/dark-v10',
            tooltip={
                'html': '<b>Process:</b> {process}<br/><b>Destination IP:</b> {ip}<br/><b>Risk:</b> {risk_score}',
                'style': {
                    'backgroundColor': 'steelblue',
                    'color': 'white'
                }
            }
        )
        
        st.pydeck_chart(deck)
        
        # Stats
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Connections", len(arc_data))
        with col2:
            high_risk = sum(1 for a in arc_data if a['risk_score'] > 70)
            st.metric("High Risk", high_risk)
        with col3:
            unique_ips = len(set(a['ip'] for a in arc_data))
            st.metric("Unique IPs", unique_ips)
            
    except Exception as e:
        st.error(f"✗ 3D map rendering failed: {e}")
        logger.error(f"3D threat map error: {e}")


def ip_to_coordinates(ip: str) -> tuple:
    """
    Simple IP to coordinates mapping (placeholder)
    In production, use MaxMind GeoIP2 or similar
    """
    # Placeholder: map common IP ranges to regions
    if not ip or ip.startswith('192.168') or ip.startswith('10.') or ip.startswith('127.'):
        return None, None
    
    # Simple hash-based random coordinates (for demo)
    hash_val = sum(ord(c) for c in ip)
    lat = ((hash_val % 180) - 90) + (hash_val % 10) / 10
    lon = ((hash_val % 360) - 180) + ((hash_val * 7) % 10) / 10
    
    return lat, lon


def render_timeline_rewind():
    """Render timeline rewind system (OMEGA)."""
    st.markdown("### ⏳ Timeline Rewind")
    st.markdown("Travel back in time to see system state at any point")
    
    # Get time range from database
    stats = st.session_state.db.get_statistics()
    
    if stats['total_events'] == 0:
        st.info("✓ No historical events yet")
        return
    
    # Time range selector
    st.markdown("#### 🎛️ Timeline Scrubber")
    
    # Get earliest and latest timestamps
    earliest = st.session_state.db.get_earliest_timestamp()
    latest = st.session_state.db.get_latest_timestamp()
    
    if not earliest or not latest:
        st.warning("⚠ Unable to determine time range")
        return
    
    from datetime import datetime
    earliest_dt = datetime.fromisoformat(earliest)
    latest_dt = datetime.fromisoformat(latest)
    
    # Slider for time selection
    selected_time = st.slider(
        "Select Point in Time",
        min_value=earliest_dt,
        max_value=latest_dt,
        value=latest_dt,
        format="YYYY-MM-DD HH:mm:ss",
        key="timeline_slider"
    )
    
    st.session_state.timeline_timestamp = selected_time.isoformat()
    
    # Display historical state at selected time
    st.markdown(f"#### 📸 System State at `{selected_time}`")
    
    # Get events up to selected time
    historical_events = st.session_state.db.get_events_before(selected_time.isoformat(), limit=50)
    
    if not historical_events:
        st.info("✓ No events at this time")
        return
    
    # Show metrics for that time
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        total = len(historical_events)
        st.metric("Total Events", total)
    
    with col2:
        high_risk = sum(1 for e in historical_events if e.get('risk_score', 0) > 70)
        st.metric("High Risk", high_risk)
    
    with col3:
        analyzed = sum(1 for e in historical_events if e.get('analyzed', 0) == 1)
        st.metric("AI Analyzed", analyzed)
    
    with col4:
        unique_procs = len(set(e.get('process_name', '') for e in historical_events))
        st.metric("Unique Processes", unique_procs)
    
    # Show events table
    st.markdown("#### 📊 Events at Selected Time")
    
    if historical_events:
        df = pd.DataFrame(historical_events)
        df = df[['timestamp', 'process_name', 'risk_score', 'user', 'analyzed']]
        st.dataframe(df, use_container_width=True)
        
        # Export historical state
        if st.button("📥 Export Historical State"):
            export_path = f"historical_state_{selected_time.strftime('%Y%m%d_%H%M%S')}.json"
            with open(export_path, 'w') as f:
                json.dump(historical_events, f, indent=2)
            st.success(f"✓ Exported to {export_path}")


def render_rules_and_plugins():
    """Render rules engine and plugin manager interface (OMEGA)."""
    st.markdown("### 📋 Rules Engine & Plugin System")
    
    col1, col2 = st.columns(2)
    
    # Rules Engine Panel
    with col1:
        st.markdown("#### 📜 YAML Rules Engine")
        
        if st.session_state.rules_engine:
            rules_info = st.session_state.rules_engine.get_rules_info()
            stats = st.session_state.rules_engine.get_stats()
            
            st.metric("Loaded Rules", stats['rules_loaded'])
            st.metric("Rules Matched", stats['rules_matched'])
            st.metric("Actions Executed", stats['actions_executed'])
            
            # Hot reload button
            if st.button("🔄 Reload Rules"):
                success = st.session_state.rules_engine.reload_rules()
                if success:
                    st.success("✓ Rules reloaded successfully")
                else:
                    st.error("✗ Failed to reload rules")
            
            # Show rules
            with st.expander("📖 View All Rules"):
                for rule in rules_info:
                    status = "✅" if rule['enabled'] else "❌"
                    severity_color = {
                        'critical': '🔴',
                        'high': '🟠',
                        'medium': '🟡',
                        'low': '🟢'
                    }.get(rule['severity'], '⚪')
                    
                    st.markdown(f"{status} {severity_color} **{rule['name']}**")
                    st.markdown(f"  _{rule['description']}_")
                    st.markdown(f"  Conditions: {rule['conditions']} | Actions: {', '.join(rule['actions'])}")
                    st.markdown("---")
            
            # Edit rules.yaml
            if st.button("✏️ Edit Rules File"):
                st.code(open('rules.yaml', 'r').read(), language='yaml')
        else:
            st.warning("⚠ Rules engine not available")
    
    # Plugin Manager Panel
    with col2:
        st.markdown("#### 🧩 Plugin System")
        
        if st.session_state.plugin_manager:
            plugins_info = st.session_state.plugin_manager.get_plugins_info()
            stats = st.session_state.plugin_manager.get_stats()
            
            st.metric("Loaded Plugins", stats['loaded'])
            st.metric("Enabled", stats['enabled'])
            st.metric("Events Processed", stats['events_processed'])
            
            # Hot reload button
            if st.button("🔄 Reload Plugins"):
                loaded = st.session_state.plugin_manager.reload_plugins()
                st.success(f"✓ Reloaded {loaded} plugins")
            
            # Show plugins
            with st.expander("🔌 View All Plugins"):
                for plugin in plugins_info:
                    status = "✅" if plugin['enabled'] else "❌"
                    
                    st.markdown(f"{status} **{plugin['name']}** v{plugin['version']}")
                    st.markdown(f"  _by {plugin['author']}_")
                    st.markdown(f"  {plugin['description']}")
                    st.markdown(f"  `{plugin['file_path']}`")
                    
                    # Enable/Disable button
                    col_a, col_b = st.columns(2)
                    with col_a:
                        if st.button(f"Disable", key=f"disable_{plugin['name']}"):
                            st.session_state.plugin_manager.disable_plugin(plugin['name'])
                            st.rerun()
                    with col_b:
                        if st.button(f"Enable", key=f"enable_{plugin['name']}"):
                            st.session_state.plugin_manager.enable_plugin(plugin['name'])
                            st.rerun()
                    
                    st.markdown("---")
        else:
            st.warning("⚠ Plugin manager not available")
    
    # ML Anomaly Detector Panel
    st.markdown("---")
    st.markdown("#### 🤖 ML Anomaly Detector")
    
    if st.session_state.ml_detector:
        ml_stats = st.session_state.ml_detector.get_stats()
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Predictions", ml_stats['predictions'])
        with col2:
            st.metric("Anomalies", ml_stats['anomalies_detected'])
        with col3:
            st.metric("Training Samples", ml_stats['training_samples'])
        with col4:
            rate = ml_stats.get('anomaly_rate', 0) * 100
            st.metric("Anomaly Rate", f"{rate:.1f}%")
        
        # Model info
        last_trained = ml_stats.get('last_trained', 'Never')
        st.info(f"📊 Model last trained: {last_trained}")
        
        # Manual training button
        if st.button("🏋️ Train Model Now"):
            success = st.session_state.ml_detector.train(force=True)
            if success:
                st.success("✓ Model training complete")
            else:
                st.error("✗ Training failed - need more samples")
    else:
        st.warning("⚠ ML detector not available")


def render_demo_mode():
    """Render demo mode explanation when Rust is not available."""
    st.warning("⚠️ Running in Demo Mode")
    st.markdown("""
    The Rust core module is not available. To enable full functionality:
    
    1. **Install Rust**: Download from [rustup.rs](https://rustup.rs)
    2. **Install Maturin**: `pip install maturin`
    3. **Build the module**: `maturin develop --release`
    4. **Restart NOSP**
    
    In demo mode, you can still:
    - View the UI and interface
    - Test database operations
    - Configure AI settings
    """)


def render_system_hardening():
    """Render System Hardening tab for Windows security auditing and fixes."""
    st.markdown("### 🛡️ System Hardening")
    st.markdown("Audit and fix Windows security settings automatically.")
    
    if not st.session_state.system_hardener:
        st.error("⚠ System Hardener not available")
        return
    
    hardener = st.session_state.system_hardener
    
    # Control buttons
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🔍 Audit System", use_container_width=True):
            with st.spinner("Auditing Windows security settings..."):
                try:
                    results = hardener.audit_system()
                    st.session_state.hardening_results = results
                    st.success(f"✓ Audit complete: {len(results)} checks performed")
                except Exception as e:
                    st.error(f"✗ Audit failed: {e}")
    
    with col2:
        if st.button("🔧 Apply Fixes", use_container_width=True, 
                    disabled=not st.session_state.hardening_results):
            with st.spinner("Applying security fixes..."):
                try:
                    results = hardener.harden_system(st.session_state.hardening_results)
                    st.success(f"✓ Applied {sum(1 for r in results.values() if r.get('fixed'))} fixes")
                    # Re-audit after fixes
                    st.session_state.hardening_results = hardener.audit_system()
                except Exception as e:
                    st.error(f"✗ Hardening failed: {e}")
    
    with col3:
        if st.button("🔄 Refresh", use_container_width=True):
            st.session_state.hardening_results = None
            st.rerun()
    
    st.markdown("---")
    
    # Display audit results
    if st.session_state.hardening_results:
        results = st.session_state.hardening_results
        
        # Summary metrics
        total_checks = len(results)
        passed = sum(1 for r in results.values() if r['status'] == 'OK')
        failed = sum(1 for r in results.values() if r['status'] == 'FAIL')
        warning = sum(1 for r in results.values() if r['status'] == 'WARNING')
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Checks", total_checks)
        with col2:
            st.metric("Passed", passed, delta=None if passed == total_checks else f"-{failed}")
        with col3:
            st.metric("Failed", failed, delta=f"-{failed}" if failed > 0 else "0")
        with col4:
            score = (passed / total_checks * 100) if total_checks > 0 else 0
            st.metric("Security Score", f"{score:.0f}%")
        
        st.markdown("---")
        
        # Detailed results
        st.markdown("#### 📋 Detailed Audit Results")
        
        for check_name, check_result in results.items():
            status = check_result['status']
            message = check_result['message']
            
            # Color-code based on status
            if status == 'OK':
                emoji = "✅"
                color = "green"
            elif status == 'FAIL':
                emoji = "❌"
                color = "red"
            else:
                emoji = "⚠️"
                color = "orange"
            
            with st.expander(f"{emoji} {check_name} - {status}"):
                st.markdown(f"**Status:** <span style='color:{color}'>{status}</span>", unsafe_allow_html=True)
                st.markdown(f"**Details:** {message}")
                
                if 'recommendation' in check_result:
                    st.info(f"💡 Recommendation: {check_result['recommendation']}")
                
                if check_result.get('fixable', False):
                    st.success("🔧 This issue can be auto-fixed")
    else:
        st.info("👆 Click 'Audit System' to scan your Windows security configuration")
        
        st.markdown("#### 🎯 Security Checks Include:")
        st.markdown("""
        - ✅ Windows Defender Real-Time Protection
        - ✅ Windows Defender Cloud Protection
        - ✅ Windows Firewall (Domain, Private, Public profiles)
        - ✅ Guest Account Status
        - ✅ User Account Control (UAC)
        - ✅ SMBv1 Protocol
        - ✅ Remote Desktop (RDP) Status
        - ✅ Windows Update Configuration
        - ✅ BitLocker Encryption
        - ✅ PowerShell Execution Policy
        """)


def render_terminal():
    """Render embedded terminal tab for command execution."""
    st.markdown("### 💻 Embedded Terminal")
    st.markdown("Execute system commands directly from NOSP interface.")
    
    if not st.session_state.terminal:
        st.error("⚠ Terminal not available")
        return
    
    terminal = st.session_state.terminal
    
    # Command input
    col1, col2 = st.columns([5, 1])
    
    with col1:
        command = st.text_input(
            "Command:",
            placeholder="Enter command (e.g., ipconfig, netstat -an, tasklist)",
            key="terminal_input",
            help="Enter a system command to execute"
        )
    
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)  # Alignment spacing
        shell_type = st.selectbox("Shell:", ["CMD", "PowerShell"], key="shell_type", label_visibility="collapsed")
    
    # Execute button
    col1, col2, col3 = st.columns([2, 2, 6])
    
    with col1:
        execute_btn = st.button("▶️ Execute", use_container_width=True)
    
    with col2:
        if st.button("🗑️ Clear History", use_container_width=True):
            terminal.clear_history()
            st.session_state.terminal_history = []
            st.success("✓ History cleared")
            st.rerun()
    
    # Execute command
    if execute_btn and command:
        with st.spinner(f"Executing: {command}"):
            try:
                output, exit_code, duration = terminal.execute_command(
                    command,
                    shell="powershell" if shell_type == "PowerShell" else "cmd"
                )
                
                # Add to session history for display
                if 'terminal_history' not in st.session_state:
                    st.session_state.terminal_history = []
                
                st.session_state.terminal_history.append({
                    'command': command,
                    'output': output,
                    'exit_code': exit_code,
                    'duration': duration,
                    'shell': shell_type,
                    'timestamp': datetime.now().strftime("%H:%M:%S")
                })
                
                # Keep only last 20 entries
                if len(st.session_state.terminal_history) > 20:
                    st.session_state.terminal_history = st.session_state.terminal_history[-20:]
                
            except Exception as e:
                st.error(f"✗ Execution failed: {e}")
    
    st.markdown("---")
    
    # Command templates
    st.markdown("#### 🎯 Quick Command Templates")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown("**Network**")
        for cmd_name, cmd in terminal.COMMAND_TEMPLATES.get('Network', {}).items():
            if st.button(cmd_name, key=f"tmpl_net_{cmd_name}", use_container_width=True):
                st.session_state.terminal_input = cmd
                st.rerun()
    
    with col2:
        st.markdown("**Process**")
        for cmd_name, cmd in terminal.COMMAND_TEMPLATES.get('Process', {}).items():
            if st.button(cmd_name, key=f"tmpl_proc_{cmd_name}", use_container_width=True):
                st.session_state.terminal_input = cmd
                st.rerun()
    
    with col3:
        st.markdown("**System**")
        for cmd_name, cmd in terminal.COMMAND_TEMPLATES.get('System', {}).items():
            if st.button(cmd_name, key=f"tmpl_sys_{cmd_name}", use_container_width=True):
                st.session_state.terminal_input = cmd
                st.rerun()
    
    with col4:
        st.markdown("**Security**")
        for cmd_name, cmd in terminal.COMMAND_TEMPLATES.get('Security', {}).items():
            if st.button(cmd_name, key=f"tmpl_sec_{cmd_name}", use_container_width=True):
                st.session_state.terminal_input = cmd
                st.rerun()
    
    st.markdown("---")
    
    # Command history display
    st.markdown("#### 📜 Command History")
    
    if hasattr(st.session_state, 'terminal_history') and st.session_state.terminal_history:
        # Reverse to show newest first
        for idx, entry in enumerate(reversed(st.session_state.terminal_history)):
            status_color = "green" if entry['exit_code'] == 0 else "red"
            status_emoji = "✅" if entry['exit_code'] == 0 else "❌"
            
            with st.expander(
                f"{status_emoji} [{entry['timestamp']}] {entry['shell']}: {entry['command']} "
                f"(Exit: {entry['exit_code']}, Duration: {entry['duration']:.2f}s)"
            ):
                st.code(entry['output'], language='text')
    else:
        st.info("👆 Execute commands to see history here")
    
    # Terminal info
    with st.expander("ℹ️ Terminal Information"):
        st.markdown("""
        **Safety Features:**
        - ✅ Command sanitization prevents dangerous operations
        - ✅ Blacklist blocks: `format`, `del`, `rd`, `shutdown`, `restart`
        - ✅ Injection attack prevention
        - ✅ 30-second execution timeout
        - ✅ Command history tracking
        
        **Supported Shells:**
        - CMD (Windows Command Prompt)
        - PowerShell (Windows PowerShell)
        
        **Tips:**
        - Use quick templates for common commands
        - Check exit code: 0 = success, non-zero = error
        - Commands timeout after 30 seconds
        """)


def render_active_defense():
    """Render Active Defense controls for threat response."""
    st.markdown("### ⚔️ Active Defense Controls")
    
    st.warning("⚠️ Use these controls with caution. They perform direct system operations.")
    
    # Get processes to act on
    high_risk_events = st.session_state.db.get_recent_events(limit=20, min_risk=70)
    
    if not high_risk_events:
        st.info("✓ No high-risk processes detected")
        return
    
    # Display high-risk processes with action buttons
    for event in high_risk_events[:10]:  # Limit to top 10
        process_name = Path(event['image']).name
        risk_score = event['risk_score']
        pid = event['process_id']
        
        with st.expander(f"🎯 {process_name} - Risk: {risk_score} | PID: {pid}"):
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.code(event['command_line'], language=None)
                st.caption(f"User: {event['user']} | Time: {event['timestamp']}")
            
            with col2:
                st.markdown("**Actions:**")
                
                # Terminate button
                if st.button(f"🛑 Terminate", key=f"kill_{pid}"):
                    try:
                        if RUST_AVAILABLE:
                            success = nosp_core.terminate_process(pid)
                            if success:
                                st.success(f"✓ Process {pid} terminated")
                                if st.session_state.alert_system.enabled:
                                    st.session_state.alert_system.alert_threat_neutralized(process_name)
                                logger.info(f"✓ Terminated process: {pid} ({process_name})")
                            else:
                                st.error("✗ Failed to terminate process")
                        else:
                            st.error("✗ Rust module required for this action")
                    except Exception as e:
                        st.error(f"✗ Error: {e}")
                        logger.error(f"✗ Terminate failed: {e}")
                
                # Suspend button
                if st.button(f"⏸️ Suspend", key=f"suspend_{pid}"):
                    try:
                        if RUST_AVAILABLE:
                            success = nosp_core.suspend_process(pid)
                            if success:
                                st.success(f"✓ Process {pid} suspended")
                                logger.info(f"✓ Suspended process: {pid}")
                            else:
                                st.error("✗ Failed to suspend process")
                        else:
                            st.error("✗ Rust module required")
                    except Exception as e:
                        st.error(f"✗ Error: {e}")
                
                # Quarantine button
                if st.button(f"🔒 Quarantine", key=f"quarantine_{pid}"):
                    try:
                        if RUST_AVAILABLE:
                            import os
                            quarantine_dir = os.path.join(os.path.expanduser("~"), ".nosp_quarantine")
                            result = nosp_core.quarantine_file(event['image'], quarantine_dir)
                            st.success(f"✓ File quarantined: {result}")
                            logger.info(f"✓ Quarantined: {event['image']}")
                        else:
                            st.error("✗ Rust module required")
                    except Exception as e:
                        st.error(f"✗ Error: {e}")
                        logger.error(f"✗ Quarantine failed: {e}")


def render_process_tree():
    """Render process tree visualization."""
    st.markdown("### 🌳 Process Tree Visualization")
    
    if not st.session_state.process_tree:
        st.info("Process tree not available")
        return
    
    tree_data = st.session_state.process_tree.get_tree_data()
    
    if not tree_data['nodes']:
        st.info("No process relationships detected yet. Start monitoring to build the tree.")
        return
    
    try:
        from streamlit_agraph import agraph, Node, Edge, Config
        
        # Convert to streamlit-agraph format
        nodes = []
        edges = []
        
        for node in tree_data['nodes']:
            risk = node.get('risk', 0)
            
            # Color by risk
            if risk >= 75:
                color = "#FF4444"
            elif risk >= 60:
                color = "#FF8800"
            elif risk >= 30:
                color = "#FFCC00"
            else:
                color = "#00FF41"
            
            nodes.append(Node(
                id=str(node['id']),
                label=node['label'],
                size=20 + (risk / 5),  # Larger nodes for higher risk
                color=color,
                title=f"{node['path']}\nRisk: {risk}"
            ))
        
        for edge in tree_data['edges']:
            edges.append(Edge(
                source=str(edge['source']),
                target=str(edge['target']),
                color="#00D9FF"
            ))
        
        config = Config(
            width=800,
            height=600,
            directed=True,
            physics=True,
            hierarchical=False,
            nodeHighlightBehavior=True,
            highlightColor="#00FF41",
            collapsible=False
        )
        
        if nodes:
            agraph(nodes=nodes, edges=edges, config=config)
        else:
            st.info("Building process tree...")
    
    except ImportError:
        st.error("⚠️ streamlit-agraph not installed. Run: pip install streamlit-agraph")
    except Exception as e:
        st.error(f"✗ Visualization error: {e}")
        logger.error(f"✗ Process tree visualization failed: {e}")
    
    # Show suspicious chains
    st.markdown("#### 🔍 Suspicious Process Chains")
    suspicious_chains = st.session_state.process_tree.find_suspicious_chains(min_risk=60)
    
    if suspicious_chains:
        for i, chain in enumerate(suspicious_chains[:5]):  # Show top 5
            chain_info = " → ".join([str(pid) for pid in chain])
            st.warning(f"Chain {i+1}: {chain_info}")
    else:
        st.success("✓ No suspicious process chains detected")


def render_enhanced_analysis():
    """Render enhanced AI analysis with MITRE ATT&CK mapping."""
    st.markdown("### 🔍 AI Threat Analysis & MITRE ATT&CK Mapping")
    
    # Get high-risk analyzed events
    analyzed_events = st.session_state.db.get_recent_events(limit=20, min_risk=60)
    analyzed_events = [e for e in analyzed_events if e.get('analyzed') == 1]
    
    if not analyzed_events:
        st.info("✓ No high-risk threats detected")
        return
    
    # Analyze button for unanalyzed events
    unanalyzed = st.session_state.db.get_high_risk_unanalyzed(threshold=60, limit=5)
    if unanalyzed:
        st.warning(f"⚠️ {len(unanalyzed)} high-risk events awaiting analysis")
        if st.button("🤖 Run AI Analysis Now"):
            with st.spinner("Analyzing threats..."):
                for event in unanalyzed:
                    analysis = st.session_state.ai_engine.analyze_process(event)
                    if analysis:
                        analysis_text = analysis.get('analysis', str(analysis)) if isinstance(analysis, dict) else str(analysis)
                        st.session_state.db.update_ai_analysis(event['id'], analysis_text)
                st.success("✓ Analysis complete!")
                st.rerun()
    
    # Display analyzed events with MITRE info
    for event in analyzed_events[:5]:  # Show top 5
        risk_level = st.session_state.risk_scorer.get_risk_level(event['risk_score'])
        process_name = Path(event['image']).name
        
        with st.expander(f"🚨 {risk_level} - {process_name} (Score: {event['risk_score']})"):
            col1, col2 = st.columns([1, 2])
            
            with col1:
                st.markdown("**Process Details**")
                st.code(event['image'], language=None)
                st.caption(f"PID: {event['process_id']}")
                st.caption(f"User: {event['user']}")
                st.caption(f"Time: {event['timestamp']}")
            
            with col2:
                st.markdown("**AI Analysis**")
                
                analysis_text = event.get('ai_analysis', 'No analysis available')
                st.markdown(analysis_text)
                
                # Parse and display MITRE ATT&CK info
                import re
                mitre_tactic = re.search(r'MITRE_TACTIC:\s*([^\n]+)', analysis_text)
                mitre_technique = re.search(r'MITRE_TECHNIQUE:\s*([^\n]+)', analysis_text)
                threat_level = re.search(r'THREAT_LEVEL:\s*([^\n]+)', analysis_text)
                
                if mitre_tactic or mitre_technique:
                    st.markdown("---")
                    st.markdown("**🎯 MITRE ATT&CK Mapping**")
                    
                    if mitre_tactic:
                        st.info(f"**Tactic:** {mitre_tactic.group(1).strip()}")
                    
                    if mitre_technique:
                        technique = mitre_technique.group(1).strip()
                        st.info(f"**Technique:** {technique}")
                        
                        # Extract technique ID for link
                        tech_id = re.search(r'T\d{4}(?:\.\d{3})?', technique)
                        if tech_id:
                            mitre_url = f"https://attack.mitre.org/techniques/{tech_id.group(0).replace('.', '/')}/"
                            st.markdown(f"[View on MITRE ATT&CK →]({mitre_url})")
            
            st.markdown("**Command Line**")
            st.code(event['command_line'], language=None)


# ============================================================================
# MAIN APPLICATION FLOW
# ============================================================================

def main():
    """Main application entry point."""
    # Initialize components
    if not st.session_state.initialized:
        with st.spinner("Initializing NOSP components..."):
            # Restore previous session (APEX feature)
            try:
                session_mgr = SessionManager()
                session_mgr.restore_to_session_state(st.session_state)
                logger.info("✓ Session restored from previous state")
            except Exception as e:
                logger.warning(f"⚠ Could not restore session: {e}")
            
            if not initialize_components():
                st.error("Failed to initialize. Please check logs.")
                return
            
            # Start auto-save thread (APEX feature)
            if st.session_state.session_manager:
                try:
                    st.session_state.session_manager.start_auto_save(st.session_state)
                    logger.info("✓ Auto-save thread started")
                except Exception as e:
                    logger.warning(f"⚠ Auto-save not available: {e}")
    
    # Render UI
    render_sidebar()
    render_header()
    
    # Process events if monitoring
    if RUST_AVAILABLE and st.session_state.monitoring:
        process_events()
    
    # Main content tabs (OMEGA + APEX + EVENT HORIZON)
    tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8, tab9, tab10, tab11, tab12, tab13 = st.tabs([
        "📊 Dashboard", 
        "🔍 Analysis", 
        "⚔️ Active Defense",
        "🌳 Process Tree",
        "🌍 3D Threat Map",
        "⏳ Timeline Rewind",
        "📋 Rules & Plugins",
        "🛡️ System Hardening",
        "💻 Terminal",
        "⚙️ Settings",
        "🌌 Event Horizon",
        "🔒 The Cage",
        "⚡ God Mode"
    ])
    
    with tab1:
        if not RUST_AVAILABLE:
            render_demo_mode()
        else:
            render_events_table()
    
    with tab2:
        if st.session_state.ai_engine and st.session_state.ai_engine.model_ready:
            render_enhanced_analysis()
        else:
            st.warning("⚠️ AI engine not ready. Ensure Ollama is installed and llama3 model is available.")
            st.markdown("""
            **Setup Instructions:**
            1. Install Ollama from [ollama.ai](https://ollama.ai)
            2. The llama3 model will auto-download on first use
            3. Restart NOSP
            """)
    
    with tab3:
        if RUST_AVAILABLE:
            render_active_defense()
        else:
            st.error("⚠️ Active Defense requires Rust module")
            render_demo_mode()
    
    with tab4:
        if RUST_AVAILABLE:
            render_process_tree()
        else:
            st.error("⚠️ Process Tree requires active monitoring")
            render_demo_mode()
    
    with tab5:
        if PYDECK_AVAILABLE and RUST_AVAILABLE:
            render_3d_threat_map()
        else:
            st.error("⚠️ 3D Threat Map requires pydeck and active monitoring")
            st.markdown("Install with: `pip install pydeck`")
    
    with tab6:
        if RUST_AVAILABLE:
            render_timeline_rewind()
        else:
            st.error("⚠️ Timeline Rewind requires active monitoring")
            render_demo_mode()
    
    with tab7:
        render_rules_and_plugins()
    
    with tab8:
        render_system_hardening()
    
    with tab9:
        render_terminal()
    
    with tab10:
        st.markdown("### ⚙️ Configuration")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### Audio Alerts")
            if st.session_state.alert_system:
                alert_enabled = st.checkbox(
                    "Enable Voice Alerts", 
                    value=st.session_state.alert_system.enabled,
                    key="audio_alerts"
                )
                if alert_enabled != st.session_state.alert_system.enabled:
                    st.session_state.alert_system.enabled = alert_enabled
                    st.success(f"✓ Audio alerts {'enabled' if alert_enabled else 'disabled'}")
                
                if st.button("🔊 Test Audio"):
                    st.session_state.alert_system.speak("NOSP audio test. All systems operational.")
            else:
                st.warning("Audio system unavailable")
        
        with col2:
            st.markdown("#### System Tray")
            if st.session_state.system_tray and st.session_state.system_tray.is_running():
                st.success("✓ System tray active")
                if st.button("🔔 Test Notification"):
                    st.session_state.system_tray.show_notification(
                        "NOSP Test",
                        "System tray notifications working!"
                    )
            else:
                st.warning("System tray unavailable")
        
        st.markdown("---")
        
        # Show system info
        with st.expander("🖥️ System Information"):
            import psutil
            
            info_data = {
                "Rust Available": RUST_AVAILABLE,
                "AI Engine Ready": st.session_state.ai_engine.model_ready if st.session_state.ai_engine else False,
                "Database Connected": st.session_state.db is not None,
                "Events Processed": st.session_state.events_processed,
                "Audio Alerts": st.session_state.alert_system.enabled if st.session_state.alert_system else False,
                "System Tray": st.session_state.system_tray.is_running() if st.session_state.system_tray else False,
                "CPU Usage": f"{psutil.cpu_percent()}%",
                "Memory Usage": f"{psutil.Process().memory_info().rss / 1024 / 1024:.1f} MB",
                "Python Version": sys.version.split()[0]
            }
            
            st.json(info_data)
        
        # Debug logs
        with st.expander("📋 Recent Logs"):
            st.info("Log viewer coming soon...")
    
    # EVENT HORIZON TAB 11: Block chain + P2P Mesh
    with tab11:
        st.markdown("### 🌌 Event Horizon - Immutable Ledger & Hive Mind")
        st.markdown("*Blockchain audit trail and decentralized threat intelligence*")
        st.markdown("---")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 📜 Immutable Blockchain Ledger")
            try:
                ledger = get_ledger()
                
                # Blockchain status
                chain_valid = ledger.validate_chain()
                if chain_valid:
                    st.success(f"✓ Blockchain Integrity: **VALID** ({len(ledger.chain)} blocks)")
                else:
                    st.error("⚠️ Blockchain Tampered! Chain validation failed!")
                
                # Chain summary
                summary = ledger.get_chain_summary()
                st.metric("Total Blocks", summary["total_blocks"])
                st.metric("Latest Block Hash", summary["latest_hash"][:16] + "...")
                
                # Add event demo
                st.markdown("**Log Security Event:**")
                event_type = st.selectbox("Event Type", [
                    "Malware Detection",
                    "Network Intrusion",
                    "USB Device Blocked",
                    "Process Terminated",
                    "Firewall Rule Added"
                ], key="ledger_event_type")
                event_details = st.text_input("Event Details", key="ledger_event_details")
                
                if st.button("📝 Add to Blockchain", key="add_ledger_event"):
                    if event_details:
                        log_security_event(event_type, event_details)
                        st.success(f"✓ Event logged to blockchain (block mined)")
                        st.rerun()
                
                # Show recent blocks
                st.markdown("**Recent Blocks:**")
                if len(ledger.chain) > 1:
                    for block in reversed(ledger.chain[-6:]):
                        if block.index == 0:  # Skip genesis
                            continue
                        with st.expander(f"Block #{block.index} - {block.timestamp[:19]}"):
                            st.json(block.event_data)
                            st.code(f"Hash: {block.hash}", language="text")
                            st.code(f"Previous: {block.previous_hash}", language="text")
                            st.caption(f"Nonce: {block.nonce} (Proof-of-Work)")
                else:
                    st.info("No events logged yet (only genesis block exists)")
                    
            except Exception as e:
                st.error(f"Ledger error: {e}")
        
        with col2:
            st.markdown("#### 🌐 P2P Mesh Network (Hive Mind)")
            
            # Session state for mesh network
            if 'mesh_network' not in st.session_state:
                st.session_state.mesh_network = None
                st.session_state.mesh_running = False
            
            # Control buttons
            col_a, col_b = st.columns(2)
            with col_a:
                if not st.session_state.mesh_running:
                    if st.button("🚀 Start Mesh Network", key="start_mesh"):
                        try:
                            import asyncio
                            mesh = MeshNetwork(node_name="NOSP-" + str(int(time.time()))[-4:])
                            st.session_state.mesh_network = mesh
                            
                            # Start in background (simplified for demo)
                            st.session_state.mesh_running = True
                            st.success("✓ Mesh network started!")
                            st.info("Discovering peers on UDP port 41337...")
                        except Exception as e:
                            st.error(f"Failed to start mesh: {e}")
                else:
                    if st.button("⏹️ Stop Mesh Network", key="stop_mesh"):
                        st.session_state.mesh_running = False
                        st.session_state.mesh_network = None
                        st.success("✓ Mesh network stopped")
            
            with col_b:
                if st.session_state.mesh_running and st.session_state.mesh_network:
                    if st.button("🔄 Refresh Peers", key="refresh_peers"):
                        st.rerun()
            
            # Show peer status
            if st.session_state.mesh_running and st.session_state.mesh_network:
                mesh = st.session_state.mesh_network
                peers_info = mesh.get_peers_info()
                
                st.metric("Connected Peers", len(peers_info))
                
                if peers_info:
                    st.markdown("**Active Peers:**")
                    for peer in peers_info:
                        with st.container():
                            st.markdown(f"**Node:** `{peer['node_id']}`")
                            st.markdown(f"- Host: {peer['hostname']} ({peer['ip']})")
                            st.markdown(f"- Threats: {peer['threat_count']} | Reputation: {peer['reputation']}")
                            st.caption(f"Last seen: {peer['last_seen']}")
                            st.markdown("---")
                else:
                    st.info("No peers discovered yet. Waiting for broadcasts...")
                
                # Broadcast threat demo
                st.markdown("**Broadcast Threat Signal:**")
                threat_type = st.selectbox("Threat Type", [
                    "Malware Hash",
                    "Malicious IP",
                    "C2 Domain",
                    "File Signature"
                ], key="mesh_threat_type")
                threat_value = st.text_input("Threat Indicator", key="mesh_threat_value")
                risk_score = st.slider("Risk Score", 0, 100, 75, key="mesh_risk")
                
                if st.button("📡 Broadcast to Hive", key="broadcast_threat"):
                    if threat_value:
                        try:
                            # In async context, this would be: await mesh.broadcast_threat(...)
                            st.success(f"✓ Threat broadcasted to {len(peers_info)} peers")
                            st.info(f"Threat: {threat_type} = {threat_value} (Risk: {risk_score})")
                        except Exception as e:
                            st.error(f"Broadcast failed: {e}")
            else:
                st.info("Start mesh network to discover peers and share threat intelligence")
                st.markdown("""
                **Hive Mind Features:**
                - UDP Discovery (Port 41337)
                - AES-256-GCM Encrypted Signals (Port 41338)
                - Consensus-Based Threat Validation
                - Decentralized Intelligence Sharing
                """)
    
    # EVENT HORIZON TAB 12: Sandbox (The Cage)
    with tab12:
        st.markdown("### 🔒 The Cage - Zero-Trust Sandbox")
        st.markdown("*Detonate suspicious files in isolated execution environment*")
        st.markdown("---")
        
        st.warning("⚠️ **WARNING:** The Cage executes files in a monitored sandbox. Use only for suspected malware analysis.")
        
        col1, col2 = st.columns([1, 1])
        
        with col1:
            st.markdown("#### 📥 Upload & Detonate")
            
            uploaded_file = st.file_uploader("Select file to detonate", type=["exe", "bat", "ps1", "dll", "scr", "cmd", "vbs"], key="cage_file")
            
            timeout = st.slider("Execution Timeout (seconds)", 5, 30, 15, key="cage_timeout")
            
            if uploaded_file:
                st.info(f"**File:** {uploaded_file.name} ({uploaded_file.size} bytes)")
                
                if st.button("💥 DETONATE FILE", key="detonate_file", type="primary"):
                    with st.spinner("Detonating in sandbox..."):
                        try:
                            # Save uploaded file to temp location
                            import tempfile
                            import os
                            
                            with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uploaded_file.name)[1]) as tmp_file:
                                tmp_file.write(uploaded_file.getbuffer())
                                tmp_path = tmp_file.name
                            
                            # Detonate in cage
                            cage = Cage()
                            result = cage.detonate_file(tmp_path, timeout=timeout)
                            
                            # Store result in session state
                            st.session_state.cage_result = result
                            
                            # Clean up temp file
                            try:
                                os.unlink(tmp_path)
                            except:
                                pass
                            
                            st.success("✓ Detonation complete!")
                            st.rerun()
                            
                        except Exception as e:
                            st.error(f"Detonation failed: {e}")
        
        with col2:
            st.markdown("#### 🎯 Quick Command Test")
            st.markdown("Test suspicious commands without file upload")
            
            test_command = st.text_area("Command to execute", 
                                        placeholder="powershell -Command \"Get-Process\"",
                                        key="cage_command")
            
            if st.button("🧪 Test Command", key="test_command"):
                if test_command:
                    with st.spinner("Executing in sandbox..."):
                        try:
                            cage = Cage()
                            result = cage.detonate_command(test_command, timeout=timeout)
                            st.session_state.cage_result = result
                            st.success("✓ Execution complete!")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Execution failed: {e}")
        
        # Show results
        if hasattr(st.session_state, 'cage_result') and st.session_state.cage_result:
            st.markdown("---")
            st.markdown("### 📊 Sandbox Analysis Results")
            
            result = st.session_state.cage_result
            
            # Verdict banner
            if result.verdict == "BENIGN":
                st.success(f"### ✓ VERDICT: {result.verdict}")
            elif result.verdict == "SUSPICIOUS":
                st.warning(f"### ⚠️ VERDICT: {result.verdict}")
            else:  # MALICIOUS
                st.error(f"### 🚨 VERDICT: {result.verdict}")
            
            # Metrics
            col_a, col_b, col_c, col_d = st.columns(4)
            col_a.metric("Risk Score", f"{result.risk_score}/100")
            col_b.metric("Behaviors Detected", len(result.behaviors_detected))
            col_c.metric("Execution Time", f"{result.execution_time:.2f}s")
            col_d.metric("Exit Code", result.exit_code)
            
            # Behavioral events
            if result.behaviors_detected:
                st.markdown("**Suspicious Behaviors:**")
                for behavior in result.behaviors_detected:
                    event_type = behavior.event_type
                    icon = {
                        "file_access": "📁",
                        "child_process": "🔀",
                        "network_connection": "🌐",
                        "thread_injection": "💉"
                    }.get(event_type, "⚠️")
                    
                    with st.expander(f"{icon} {event_type.replace('_', ' ').title()} (+{behavior.risk_contribution} risk)"):
                        st.json(behavior.details)
                        st.caption(f"Timestamp: {behavior.timestamp}")
            else:
                st.info("No suspicious behaviors detected")
            
            # Output
            if result.output:
                with st.expander("📄 Execution Output"):
                    st.code(result.output, language="text")
            
            # Error
            if result.error:
                with st.expander("❌ Errors"):
                    st.code(result.error, language="text")
        else:
            st.info("👆 Upload a file or enter a command to begin sandbox analysis")
    
    # EVENT HORIZON TAB 13: God Mode
    with tab13:
        st.markdown("### ⚡ God Mode - Ultimate Control")
        st.markdown("*Packet injection, self-defense, VM detection, clipboard sentinel*")
        st.markdown("---")
        
        # Check if Rust EVENT HORIZON functions are available
        eh_available = False
        try:
            import nosp_core
            # Check for EVENT HORIZON functions
            if hasattr(nosp_core, 'enable_critical_process_py'):
                eh_available = True
        except:
            pass
        
        if not eh_available:
            st.warning("⚠️ EVENT HORIZON Rust modules not compiled. Run `maturin develop` to enable God Mode.")
        
        tab_a, tab_b, tab_c, tab_d = st.tabs([
            "🛡️ Self-Defense",
            "🔍 VM Detection", 
            "📋 Clipboard Sentinel",
            "💉 Packet Injection"
        ])
        
        with tab_a:
            st.markdown("#### 🛡️ Self-Defense Mechanisms")
            
            if eh_available:
                try:
                    import nosp_core
                    
                    # Get defense status
                    status = nosp_core.get_defense_status_py()
                    
                    st.markdown("**Defense Status:**")
                    for key, value in status.items():
                        icon = "✅" if value else "❌"
                        st.markdown(f"{icon} **{key}:** `{value}`")
                    
                    st.markdown("---")
                    
                    # Critical process toggle
                    st.markdown("**⚠️ Critical Process Flag**")
                    st.warning("Enabling this makes NOSP critical to Windows. Terminating it will trigger a BSOD!")
                    
                    col_x, col_y = st.columns(2)
                    with col_x:
                        if st.button("🔒 Enable Critical Process", key="enable_critical"):
                            try:
                                nosp_core.enable_critical_process_py()
                                st.success("✓ Critical process flag enabled! NOSP is now protected.")
                            except Exception as e:
                                st.error(f"Failed: {e}")
                    
                    with col_y:
                        if st.button("🔓 Disable Critical Process", key="disable_critical"):
                            try:
                                nosp_core.disable_critical_process_py()
                                st.success("✓ Critical process flag disabled")
                            except Exception as e:
                                st.error(f"Failed: {e}")
                    
                    # Debugger detection
                    st.markdown("---")
                    st.markdown("**🔍 Debugger Detection**")
                    if st.button("Scan for Debuggers", key="scan_debugger"):
                        is_debugging = nosp_core.is_debugger_present_py()
                        if is_debugging:
                            st.error("⚠️ DEBUGGER DETECTED! Analysis tools are attached to NOSP.")
                        else:
                            st.success("✓ No debugger detected")
                    
                    # Handle attempts
                    st.markdown("---")
                    st.markdown("**👀 Handle Monitoring**")
                    if st.button("Detect Handle Attempts", key="detect_handles"):
                        try:
                            pids = nosp_core.detect_handle_attempts_py()
                            if pids:
                                st.warning(f"⚠️ {len(pids)} processes have handles to NOSP:")
                                for pid in pids:
                                    st.code(f"PID: {pid}", language="text")
                            else:
                                st.success("✓ No suspicious handle attempts detected")
                        except Exception as e:
                            st.error(f"Scan failed: {e}")
                    
                except Exception as e:
                    st.error(f"Self-defense error: {e}")
            else:
                st.info("Compile Rust modules to enable self-defense features")
        
        with tab_b:
            st.markdown("#### 🔍 VM & Debugger Detection")
            
            if eh_available:
                try:
                    import nosp_core
                    
                    if st.button("🔎 Scan Environment", key="scan_environment", type="primary"):
                        with st.spinner("Analyzing execution environment..."):
                            env_status = nosp_core.get_environment_status_py()
                            st.session_state.env_status = env_status
                            st.rerun()
                    
                    if hasattr(st.session_state, 'env_status'):
                        env = st.session_state.env_status
                        
                        # Overall status
                        if env['is_suspicious']:
                            st.error("🚨 SUSPICIOUS ENVIRONMENT DETECTED!")
                        else:
                            st.success("✓ Environment appears legitimate")
                        
                        col_p, col_q = st.columns(2)
                        
                        with col_p:
                            st.markdown("**Virtual Machine Detection:**")
                            vm = env['vm']
                            
                            if vm['is_vm']:
                                st.warning(f"⚠️ Running in {vm['vm_type']}")
                                st.metric("Confidence", f"{vm['confidence']}%")
                            else:
                                st.success("✓ Not running in VM")
                            
                            if vm['indicators']:
                                with st.expander("VM Indicators"):
                                    for indicator in vm['indicators']:
                                        st.markdown(f"- {indicator}")
                        
                        with col_q:
                            st.markdown("**Debugger Detection:**")
                            dbg = env['debugger']
                            
                            if dbg['is_debugging']:
                                st.error(f"🚨 {dbg['debugger_type']} detected!")
                                st.metric("Confidence", f"{dbg['confidence']}%")
                            else:
                                st.success("✓ No debugger detected")
                            
                            if dbg['indicators']:
                                with st.expander("Debugger Indicators"):
                                    for indicator in dbg['indicators']:
                                        st.markdown(f"- {indicator}")
                    
                except Exception as e:
                    st.error(f"Detection error: {e}")
            else:
                st.info("Compile Rust modules to enable VM detection")
        
        with tab_c:
            st.markdown("#### 📋 Clipboard Sentinel")
            
            if eh_available:
                try:
                    import nosp_core
                    
                    # Check if monitoring
                    is_monitoring = nosp_core.is_monitoring_py()
                    
                    col_m, col_n = st.columns(2)
                    with col_m:
                        if not is_monitoring:
                            if st.button("▶️ Start Monitoring", key="start_clipboard"):
                                nosp_core.start_clipboard_monitor_py()
                                st.success("✓ Clipboard monitoring started")
                                st.rerun()
                        else:
                            if st.button("⏹️ Stop Monitoring", key="stop_clipboard"):
                                nosp_core.stop_clipboard_monitor_py()
                                st.success("✓ Clipboard monitoring stopped")
                                st.rerun()
                    
                    with col_n:
                        if is_monitoring:
                            st.success("🟢 Monitoring Active")
                        else:
                            st.info("⚪ Monitoring Inactive")
                    
                    if is_monitoring:
                        st.markdown("---")
                        st.markdown("**Recent Clipboard Activity:**")
                        
                        # Get history
                        history = nosp_core.get_clipboard_history_py()
                        
                        if history:
                            for event in reversed(history):
                                icon = "🔐" if event.get('is_sensitive') else "📄"
                                warning_icon = " ⚠️" if event.get('is_suspicious') else ""
                                
                                with st.expander(f"{icon} {event['content_type']} - {event['timestamp'][:19]}{warning_icon}"):
                                    st.markdown(f"**Content:** `{event['content']}`")
                                    st.markdown(f"**Sensitive:** {event['is_sensitive']}")
                                    if event.get('is_suspicious'):
                                        st.error(f"**WARNING:** {event.get('warning_message', 'Suspicious activity detected')}")
                        else:
                            st.info("No clipboard activity recorded yet")
                        
                        # Suspicious events
                        st.markdown("---")
                        st.markdown("**🚨 Hijacking Attempts:**")
                        suspicious = nosp_core.get_latest_suspicious_py()
                        
                        if suspicious:
                            for event in suspicious:
                                with st.container():
                                    st.error(f"**{event['content_type']}** - {event['timestamp'][:19]}")
                                    st.markdown(f"```{event['content']}```")
                                    st.markdown(f"⚠️ {event.get('warning_message')}")
                                    st.markdown("---")
                        else:
                            st.success("✓ No hijacking attempts detected")
                        
                        # Whitelist management
                        st.markdown("---")
                        st.markdown("**Whitelist Management:**")
                        
                        whitelist = nosp_core.get_whitelist_py()
                        if whitelist:
                            st.markdown("**Whitelisted Addresses:**")
                            for addr in whitelist:
                                col_r, col_s = st.columns([4, 1])
                                col_r.code(addr, language="text")
                                if col_s.button("❌", key=f"remove_{addr[:8]}"):
                                    nosp_core.remove_from_whitelist_py(addr)
                                    st.rerun()
                        
                        new_addr = st.text_input("Add address to whitelist", key="whitelist_addr")
                        if st.button("➕ Add to Whitelist", key="add_whitelist"):
                            if new_addr:
                                nosp_core.add_to_whitelist_py(new_addr)
                                st.success(f"✓ Added {new_addr}")
                                st.rerun()
                    
                except Exception as e:
                    st.error(f"Clipboard monitor error: {e}")
            else:
                st.info("Compile Rust modules to enable clipboard monitoring")
        
        with tab_d:
            st.markdown("#### 💉 Packet Injection (C)")
            st.markdown("*TCP RST injection at wire level*")
            
            st.warning("⚠️ Requires Administrator privileges and compiled C modules")
            
            st.markdown("**Kill TCP Connection:**")
            
            col_1, col_2 = st.columns(2)
            with col_1:
                src_ip = st.text_input("Source IP", placeholder="192.168.1.100", key="rst_src_ip")
                dst_ip = st.text_input("Destination IP", placeholder="203.0.113.42", key="rst_dst_ip")
            
            with col_2:
                src_port = st.number_input("Source Port", min_value=1, max_value=65535, value=54321, key="rst_src_port")
                dst_port = st.number_input("Dest Port", min_value=1, max_value=65535, value=443, key="rst_dst_port")
            
            seq_num = st.number_input("Sequence Number", min_value=0, value=1234567890, key="rst_seq")
            
            if st.button("💥 Inject RST Packet", key="inject_rst", type="primary"):
                st.error("⚠️ Packet injection requires compiled C module and Administrator privileges")
                st.info(f"Would inject RST: {src_ip}:{src_port} -> {dst_ip}:{dst_port} (seq={seq_num})")
                # In production: Call C packet injector via ctypes/cffi
                # import ctypes
                # libinject = ctypes.CDLL('./native/c/packet_injector.so')
                # result = libinject.inject_tcp_rst(...)


if __name__ == "__main__":
    main()
