"""
NOSP System Tray Integration
Runs NOSP in Windows system tray with status indicators.
"""

import threading
import logging
from typing import Callable, Optional
import sys

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    import pystray
    from PIL import Image, ImageDraw
    TRAY_AVAILABLE = True
except ImportError:
    TRAY_AVAILABLE = False
    logger.warning("⚠ System tray not available. Install with: pip install pystray pillow")


class NOSPSystemTray:
    """
    System tray integration for NOSP.
    Shows status icon and provides quick access menu.
    """
    
    def __init__(self, on_open_dashboard: Callable = None, 
                 on_stop_monitoring: Callable = None,
                 on_quit: Callable = None):
        """
        Initialize system tray.
        
        Args:
            on_open_dashboard: Callback to open dashboard
            on_stop_monitoring: Callback to stop/start monitoring
            on_quit: Callback to quit application
        """
        if not TRAY_AVAILABLE:
            raise ImportError("pystray not available")
        
        self.on_open_dashboard = on_open_dashboard
        self.on_stop_monitoring = on_stop_monitoring
        self.on_quit = on_quit
        
        self.icon = None
        self.thread = None
        self.monitoring = False
        self.threat_level = 'safe'  # 'safe', 'warning', 'critical'
    
    def _create_icon_image(self, color: str = 'green') -> Image.Image:
        """Create a colored shield icon for the tray."""
        # Create a simple colored circle as icon
        size = 64
        image = Image.new('RGB', (size, size), color='white')
        draw = ImageDraw.Draw(image)
        
        # Color mapping
        colors = {
            'green': (0, 255, 65),
            'yellow': (255, 200, 0),
            'red': (255, 68, 68)
        }
        
        fill_color = colors.get(color, colors['green'])
        
        # Draw shield shape (simplified as circle for now)
        draw.ellipse([8, 8, size-8, size-8], fill=fill_color, outline='black', width=2)
        
        # Draw "N" in center
        draw.text((size//2 - 10, size//2 - 15), 'N', fill='white')
        
        return image
    
    def _menu_open_dashboard(self, icon, item):
        """Menu callback to open dashboard."""
        if self.on_open_dashboard:
            self.on_open_dashboard()
    
    def _menu_toggle_monitoring(self, icon, item):
        """Menu callback to toggle monitoring."""
        self.monitoring = not self.monitoring
        if self.on_stop_monitoring:
            self.on_stop_monitoring(self.monitoring)
        
        # Update icon
        self.update_status('safe' if self.monitoring else 'warning')
    
    def _menu_quit(self, icon, item):
        """Menu callback to quit."""
        if self.on_quit:
            self.on_quit()
        icon.stop()
    
    def _create_menu(self) -> pystray.Menu:
        """Create the system tray menu."""
        return pystray.Menu(
            pystray.MenuItem('Open Dashboard', self._menu_open_dashboard, default=True),
            pystray.MenuItem(
                lambda text: 'Stop Monitoring' if self.monitoring else 'Start Monitoring',
                self._menu_toggle_monitoring
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem('Quit NOSP', self._menu_quit)
        )
    
    def update_status(self, status: str):
        """
        Update the tray icon based on threat status.
        
        Args:
            status: 'safe', 'warning', or 'critical'
        """
        self.threat_level = status
        
        if self.icon:
            color_map = {
                'safe': 'green',
                'warning': 'yellow',
                'critical': 'red'
            }
            color = color_map.get(status, 'green')
            self.icon.icon = self._create_icon_image(color)
            
            # Update title
            title_map = {
                'safe': 'NOSP - System Secure',
                'warning': 'NOSP - Monitoring Paused',
                'critical': 'NOSP - THREAT DETECTED!'
            }
            self.icon.title = title_map.get(status, 'NOSP')
    
    def run(self):
        """Run the system tray (blocking)."""
        if not TRAY_AVAILABLE:
            logger.error("System tray not available")
            return
        
        icon_image = self._create_icon_image('green')
        menu = self._create_menu()
        
        self.icon = pystray.Icon(
            'NOSP',
            icon_image,
            'NOSP - System Secure',
            menu
        )
        
        logger.info("✓ System tray started")
        self.icon.run()
    
    def run_async(self):
        """Run the system tray in a separate thread."""
        if self.thread and self.thread.is_alive():
            logger.warning("System tray already running")
            return
        
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        logger.info("✓ System tray started (async)")
    
    def stop(self):
        """Stop the system tray."""
        if self.icon:
            self.icon.stop()
            logger.info("✓ System tray stopped")


class NOSPNotifications:
    """
    Desktop notifications for NOSP alerts.
    """
    
    def __init__(self):
        """Initialize notification system."""
        try:
            from plyer import notification
            self.notifier = notification
            self.available = True
        except ImportError:
            logger.warning("⚠ plyer not available. Install with: pip install plyer")
            self.available = False
    
    def send_notification(self, title: str, message: str, 
                         urgency: str = 'normal', timeout: int = 10):
        """
        Send a desktop notification.
        
        Args:
            title: Notification title
            message: Notification message
            urgency: 'low', 'normal', or 'critical'
            timeout: Timeout in seconds
        """
        if not self.available:
            logger.info(f"Notification: {title} - {message}")
            return
        
        try:
            self.notifier.notify(
                title=title,
                message=message,
                app_name='NOSP',
                timeout=timeout
            )
            logger.info(f"✓ Notification sent: {title}")
        except Exception as e:
            logger.error(f"✗ Notification failed: {e}")
    
    def alert_high_risk(self, process_name: str, risk_score: int):
        """Send alert for high-risk process."""
        self.send_notification(
            title='🚨 NOSP Security Alert',
            message=f'High-risk process detected: {process_name} (Risk: {risk_score})',
            urgency='critical',
            timeout=30
        )
    
    def alert_critical_threat(self, process_name: str):
        """Send alert for critical threat."""
        self.send_notification(
            title='⚠️ NOSP CRITICAL THREAT',
            message=f'CRITICAL: Potential malware detected - {process_name}',
            urgency='critical',
            timeout=60
        )
    
    def info_monitoring_started(self):
        """Send info that monitoring started."""
        self.send_notification(
            title='NOSP Monitoring',
            message='Real-time security monitoring is now active',
            urgency='low',
            timeout=5
        )
