"""
NOSP Alert System
Audio alerts, text-to-speech, and advanced notification system.
"""

import logging
from typing import Dict, Optional
import threading
import queue
from .errors import report_exception, graceful, Result

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    import pyttsx3
    TTS_AVAILABLE = True
except ImportError as e:
    TTS_AVAILABLE = False
    logger.warning("⚠ pyttsx3 not available. Install with: pip install pyttsx3")
    report_exception(e, context="alerts_import")


class AudioAlertSystem :
    """
    Text-to-speech alert system for NOSP.
    Provides voice feedback for critical security events.
    """

    def __init__ (self ):
        """Initialize the audio alert system."""
        self .enabled =TTS_AVAILABLE
        self .engine =None
        self .alert_queue =queue .Queue ()
        self .worker_thread =None
        self .running =False

        if TTS_AVAILABLE :
            try :
                self .engine =pyttsx3 .init ()
                self ._configure_engine ()
                self ._start_worker ()
                logger .info ("✓ Audio alert system initialized")
            except Exception as e:
                logger.error(f"✗ Failed to initialize TTS: {e}")
                report_exception(e, context="AudioAlertSystem.__init__")
                self.enabled = False

    def _configure_engine (self ):
        """Configure TTS engine voice and rate."""
        if not self .engine :
            return

        try :
            voices =self .engine .getProperty ('voices')
            if voices :
                for voice in voices :
                    if 'david'in voice .name .lower ()or 'mark'in voice .name .lower ():
                        self .engine .setProperty ('voice',voice .id )
                        break

            self .engine .setProperty ('rate',150 )

            self .engine .setProperty ('volume',0.9 )
        except Exception as e:
            logger.error(f"✗ Failed to configure TTS engine: {e}")
            report_exception(e, context="AudioAlertSystem._configure_engine")

    def _start_worker (self ):
        """Start worker thread to process alerts."""
        if self .worker_thread and self .worker_thread .is_alive ():
            return

        self .running =True
        self .worker_thread =threading .Thread (target =self ._process_alerts ,daemon =True )
        self .worker_thread .start ()

    def _process_alerts (self ):
        """Worker thread to process alert queue."""
        while self .running :
            try :
                message =self .alert_queue .get (timeout =1 )
                if message and self .engine :
                    logger .info (f"🔊 Speaking: {message }")
                    self .engine .say (message )
                    self .engine .runAndWait ()
            except queue .Empty :
                continue
            except Exception as e:
                logger.error(f"✗ TTS error: {e}")
                report_exception(e, context="AudioAlertSystem._process_alerts")

    def speak (self ,message :str ,priority :bool =False ):
        """
        Speak a message.
        
        Args:
            message: Text to speak
            priority: If True, speak immediately (blocking)
        """
        if not self .enabled :
            logger .info (f"Audio (disabled): {message }")
            return

        if priority :
            try :
                self .engine .say (message )
                self .engine .runAndWait ()
            except Exception as e:
                logger.error(f"✗ Immediate TTS failed: {e}")
                report_exception(e, context="AudioAlertSystem.speak")
        else:
            self.alert_queue.put(message)

    def alert_critical_threat (self ,process_name :str ,risk_score :int ):
        """Voice alert for critical threat."""
        message =f"Warning. Critical threat detected. {process_name }. Risk score {risk_score }."
        self .speak (message ,priority =True )

    def alert_high_risk (self ,process_name :str ,risk_score :int ):
        """Voice alert for high risk."""
        message =f"High risk process detected. {process_name }."
        self .speak (message ,priority =False )

    def alert_monitoring_started (self ):
        """Voice alert for monitoring start."""
        self .speak ("NOSP security monitoring activated.",priority =False )

    def alert_monitoring_stopped (self ):
        """Voice alert for monitoring stop."""
        self .speak ("Security monitoring paused.",priority =False )

    def alert_threat_neutralized (self ,process_name :str ):
        """Voice alert for neutralized threat."""
        message =f"Threat neutralized. Process {process_name } terminated."
        self .speak (message ,priority =True )

    def alert_system_status (self ,status :str ):
        """Voice alert for system status."""
        messages ={
        'all_systems_operational':"All systems operational.",
        'database_connected':"Database connected successfully.",
        'ai_engine_ready':"AI engine ready.",
        'rust_core_active':"Rust core active."
        }

        message =messages .get (status ,status )
        self .speak (message ,priority =False )

    def stop (self ):
        """Stop the alert system."""
        self .running =False
        if self .worker_thread :
            self .worker_thread .join (timeout =2 )
        logger .info ("✓ Audio alert system stopped")


class AlertPriority :
    """Alert priority levels."""
    INFO =0
    LOW =1
    MEDIUM =2
    HIGH =3
    CRITICAL =4


class Alert :
    """Represents a security alert."""

    def __init__ (self ,
    title :str ,
    message :str ,
    priority :int =AlertPriority .MEDIUM ,
    event_id :Optional [int ]=None ,
    process_id :Optional [int ]=None ,
    risk_score :Optional [int ]=None ):
        """Initialize an alert."""
        self .title =title
        self .message =message
        self .priority =priority
        self .event_id =event_id
        self .process_id =process_id
        self .risk_score =risk_score
        self .timestamp =None

        from datetime import datetime
        self .timestamp =datetime .now ()

    def to_dict (self )->Dict :
        """Convert to dictionary."""
        return {
        'title':self .title ,
        'message':self .message ,
        'priority':self .priority ,
        'event_id':self .event_id ,
        'process_id':self .process_id ,
        'risk_score':self .risk_score ,
        'timestamp':self .timestamp .isoformat ()if self .timestamp else None
        }


class AlertManager :
    """
    Manages all alert types (audio, desktop, log).
    Coordinates between different alert systems.
    """

    def __init__ (self ,audio_system :Optional [AudioAlertSystem ]=None ):
        """Initialize alert manager."""
        self .audio =audio_system or AudioAlertSystem ()
        self .alert_history =[]
        self .max_history =1000

        try:
            from nosp.system_tray import NOSPNotifications
            self.notifications = NOSPNotifications()
        except Exception as e:
            self.notifications = None
            report_exception(e, context="AlertManager.__init__")

    def send_alert (self ,alert :Alert ):
        """
        Send an alert through all available channels.
        
        Args:
            alert: Alert object to send
        """

    @graceful()
    def send_alert_safe(self, alert: Alert) -> Result:
        return self.send_alert(alert)
        logger .warning (f"🚨 {alert .title }: {alert .message }")

        self .alert_history .append (alert )
        if len (self .alert_history )>self .max_history :
            self .alert_history .pop (0 )

        if self .notifications :
            if alert .priority >=AlertPriority .HIGH :
                self .notifications .send_notification (
                title =alert .title ,
                message =alert .message ,
                urgency ='critical'if alert .priority ==AlertPriority .CRITICAL else 'normal',
                timeout =30 if alert .priority ==AlertPriority .CRITICAL else 10
                )

        if self .audio .enabled and alert .priority >=AlertPriority .HIGH :
            if alert .priority ==AlertPriority .CRITICAL :
                self .audio .speak (
                f"Critical alert. {alert .message }",
                priority =True
                )
            else :
                self .audio .speak (alert .message ,priority =False )

    def alert_process_detected (self ,event :Dict ,risk_score :int ):
        """Alert for detected process."""
        from pathlib import Path
        process_name =Path (event .get ('image','unknown')).name

        if risk_score >=90 :
            alert =Alert (
            title ="🚨 CRITICAL THREAT DETECTED",
            message =f"Malicious process: {process_name } (Risk: {risk_score })",
            priority =AlertPriority .CRITICAL ,
            event_id =event .get ('id'),
            process_id =event .get ('process_id'),
            risk_score =risk_score
            )
        elif risk_score >=60 :
            alert =Alert (
            title ="⚠️ High Risk Process",
            message =f"Suspicious process: {process_name } (Risk: {risk_score })",
            priority =AlertPriority .HIGH ,
            event_id =event .get ('id'),
            process_id =event .get ('process_id'),
            risk_score =risk_score
            )
        else :
            return

        self .send_alert (alert )

    def alert_process_terminated (self ,process_id :int ,process_name :str ):
        """Alert for process termination."""
        alert =Alert (
        title ="✅ Threat Neutralized",
        message =f"Process {process_name } (PID: {process_id }) has been terminated",
        priority =AlertPriority .MEDIUM ,
        process_id =process_id
        )
        self .send_alert (alert )

    def alert_monitoring_status (self ,started :bool ):
        """Alert for monitoring status change."""
        if started :
            alert =Alert (
            title ="NOSP Monitoring Active",
            message ="Real-time security monitoring is now active",
            priority =AlertPriority .INFO
            )
            if self .audio .enabled :
                self .audio .alert_monitoring_started ()
        else :
            alert =Alert (
            title ="NOSP Monitoring Paused",
            message ="Security monitoring has been paused",
            priority =AlertPriority .INFO
            )
            if self .audio .enabled :
                self .audio .alert_monitoring_stopped ()

        self .send_alert (alert )

    def get_recent_alerts (self ,limit :int =50 )->list :
        """Get recent alerts."""
        return self .alert_history [-limit :][::-1 ]

    def get_critical_alerts (self )->list :
        """Get only critical alerts."""
        return [a for a in self .alert_history if a .priority ==AlertPriority .CRITICAL ]

    def clear_history (self ):
        """Clear alert history."""
        self .alert_history .clear ()
        logger .info ("✓ Alert history cleared")
