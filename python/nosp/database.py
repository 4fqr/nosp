"""
NOSP Database Module
Handles all SQLite database operations with comprehensive error handling.
"""

import sqlite3
import json
from datetime import datetime
from typing import List ,Dict ,Optional ,Tuple
from pathlib import Path
import logging
from .errors import report_exception, graceful, Result

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NOSPDatabase :
    """
    Database handler for NOSP security events.
    Provides thread-safe operations with automatic error recovery.
    """

    def __init__ (self ,db_path :str ="nosp_data/events.db"):
        """Initialize database connection and create tables if needed."""
        self .db_path =db_path

        Path (db_path ).parent .mkdir (parents =True ,exist_ok =True )

        try :
            self .conn =sqlite3 .connect (db_path ,check_same_thread =False )
            self .conn .row_factory =sqlite3 .Row
            self ._initialize_schema ()
            logger .info (f"✓ Database initialized: {db_path }")
        except sqlite3.Error as e:
            logger.error(f"✗ Database initialization failed: {e}")
            report_exception(e, context="NOSPDatabase.__init__")
            raise

    def _initialize_schema (self ):
        """Create database tables if they don't exist."""
        try :
            cursor =self .conn .cursor ()

            cursor .execute ("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    computer TEXT NOT NULL,
                    process_guid TEXT UNIQUE NOT NULL,
                    process_id INTEGER NOT NULL,
                    image TEXT NOT NULL,
                    command_line TEXT NOT NULL,
                    user TEXT NOT NULL,
                    parent_image TEXT NOT NULL,
                    parent_command_line TEXT NOT NULL,
                    hashes TEXT NOT NULL,
                    risk_score INTEGER DEFAULT 0,
                    ai_analysis TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    analyzed INTEGER DEFAULT 0
                )
            """)

            cursor .execute ("""
                CREATE TABLE IF NOT EXISTS risk_factors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id INTEGER NOT NULL,
                    factor_name TEXT NOT NULL,
                    factor_value INTEGER NOT NULL,
                    description TEXT,
                    FOREIGN KEY (event_id) REFERENCES events(id)
                )
            """)

            cursor .execute ("""
                CREATE TABLE IF NOT EXISTS system_status (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    component TEXT NOT NULL,
                    status TEXT NOT NULL,
                    message TEXT
                )
            """)

            cursor .execute ("""
                CREATE INDEX IF NOT EXISTS idx_risk_score 
                ON events(risk_score DESC)
            """)

            cursor .execute ("""
                CREATE INDEX IF NOT EXISTS idx_timestamp 
                ON events(timestamp DESC)
            """)

            cursor .execute ("""
                CREATE INDEX IF NOT EXISTS idx_analyzed 
                ON events(analyzed, risk_score DESC)
            """)

            self .conn .commit ()
            logger .info ("✓ Database schema initialized")
        except sqlite3.Error as e:
            logger.error(f"✗ Schema initialization failed: {e}")
            report_exception(e, context="NOSPDatabase._initialize_schema")
            raise

    def insert_event (self ,event :Dict ,risk_score :int ,
    risk_factors :Optional [List [Tuple [str ,int ,str ]]]=None )->Optional [int ]:
        """
        Insert a new event into the database.
        
        Args:
            event: Dictionary containing event data
            risk_score: Calculated risk score (0-100)
            risk_factors: List of (factor_name, value, description) tuples
            
        Returns:
            Event ID if successful, None otherwise
        """
        try :
            cursor =self .conn .cursor ()

            cursor .execute (
            "SELECT id FROM events WHERE process_guid = ?",
            (event .get ('process_guid',''),)
            )
            existing =cursor .fetchone ()
            if existing :
                return existing ['id']

            cursor .execute ("""
                INSERT INTO events (
                    event_id, timestamp, computer, process_guid, process_id,
                    image, command_line, user, parent_image, parent_command_line,
                    hashes, risk_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,(
            event .get ('event_id',1 ),
            event .get ('timestamp',datetime .now ().isoformat ()),
            event .get ('computer','UNKNOWN'),
            event .get ('process_guid',''),
            event .get ('process_id',0 ),
            event .get ('image',''),
            event .get ('command_line',''),
            event .get ('user',''),
            event .get ('parent_image',''),
            event .get ('parent_command_line',''),
            json .dumps (event .get ('hashes',{})),
            risk_score
            ))

            event_id =cursor .lastrowid

            if risk_factors :
                for factor_name ,value ,description in risk_factors :
                    cursor .execute ("""
                        INSERT INTO risk_factors (event_id, factor_name, factor_value, description)
                        VALUES (?, ?, ?, ?)
                    """,(event_id ,factor_name ,value ,description ))

            self .conn .commit ()
            return event_id

        except sqlite3.Error as e:
            logger.error(f"✗ Failed to insert event: {e}")
            report_exception(e, context="NOSPDatabase.insert_event")
            return None

    def update_ai_analysis (self ,event_id :int ,analysis :str )->bool :
        """Update the AI analysis for an event."""
        try :
            cursor =self .conn .cursor ()
            cursor .execute ("""
                UPDATE events 
                SET ai_analysis = ?, analyzed = 1
                WHERE id = ?
            """,(analysis ,event_id ))
            self .conn .commit ()
            return True
        except sqlite3.Error as e:
            logger.error(f"✗ Failed to update AI analysis: {e}")
            report_exception(e, context="NOSPDatabase.update_ai_analysis")
            return False

    def get_recent_events (self ,limit :int =100 ,min_risk :int =0 )->List [Dict ]:
        """Get recent events, optionally filtered by minimum risk score."""
        try :
            cursor =self .conn .cursor ()
            cursor .execute ("""
                SELECT * FROM events 
                WHERE risk_score >= ?
                ORDER BY timestamp DESC 
                LIMIT ?
            """,(min_risk ,limit ))

            rows =cursor .fetchall ()
            return [dict (row )for row in rows ]

        except sqlite3.Error as e:
            logger.error(f"✗ Failed to retrieve events: {e}")
            report_exception(e, context="NOSPDatabase.get_recent_events")
            return []

    def get_high_risk_unanalyzed (self ,threshold :int =60 ,limit :int =10 )->List [Dict ]:
        """Get high-risk events that haven't been analyzed by AI yet."""
        try :
            cursor =self .conn .cursor ()
            cursor .execute ("""
                SELECT * FROM events 
                WHERE risk_score >= ? AND analyzed = 0
                ORDER BY risk_score DESC
                LIMIT ?
            """,(threshold ,limit ))

            rows =cursor .fetchall ()
            return [dict (row )for row in rows ]

        except sqlite3.Error as e:
            logger.error(f"✗ Failed to retrieve unanalyzed events: {e}")
            report_exception(e, context="NOSPDatabase.get_high_risk_unanalyzed")
            return []

    def get_statistics (self )->Dict :
        """Get database statistics."""
        try :
            cursor =self .conn .cursor ()

            stats ={}

            cursor .execute ("SELECT COUNT(*) as count FROM events")
            stats ['total_events']=cursor .fetchone ()['count']

            cursor .execute ("SELECT COUNT(*) as count FROM events WHERE risk_score >= 60")
            stats ['high_risk_events']=cursor .fetchone ()['count']

            cursor .execute ("SELECT COUNT(*) as count FROM events WHERE risk_score >= 30 AND risk_score < 60")
            stats ['medium_risk_events']=cursor .fetchone ()['count']

            cursor .execute ("SELECT COUNT(*) as count FROM events WHERE analyzed = 1")
            stats ['analyzed_events']=cursor .fetchone ()['count']

            cursor .execute ("SELECT AVG(risk_score) as avg FROM events")
            stats ['avg_risk_score']=round (cursor .fetchone ()['avg']or 0 ,2 )

            return stats

        except sqlite3.Error as e:
            logger.error(f"✗ Failed to get statistics: {e}")
            report_exception(e, context="NOSPDatabase.get_statistics")
            return {}

    def log_status (self ,component :str ,status :str ,message :str ="")->bool :
        """Log system component status."""
        try :
            cursor =self .conn .cursor ()
            cursor .execute ("""
                INSERT INTO system_status (component, status, message)
                VALUES (?, ?, ?)
            """,(component ,status ,message ))
            self .conn .commit ()
            return True
        except sqlite3.Error as e:
            logger.error(f"✗ Failed to log status: {e}")
            report_exception(e, context="NOSPDatabase.log_status")
            return False


    def get_recent_network_events (self ,limit :int =100 )->List [Dict ]:
        """Get recent network events (Sysmon Event ID 3)"""
        try :
            cursor =self .conn .cursor ()
            cursor .execute ("""
                SELECT * FROM events 
                WHERE event_id = 3
                ORDER BY timestamp DESC 
                LIMIT ?
            """,(limit ,))

            events =[]
            for row in cursor .fetchall ():
                events .append (dict (row ))

            return events
        except sqlite3.Error as e:
            logger.error(f"Failed to fetch network events: {e}")
            report_exception(e, context="NOSPDatabase.get_recent_network_events")
            return []

    def get_earliest_timestamp (self )->Optional [str ]:
        """Get the earliest event timestamp"""
        try :
            cursor =self .conn .cursor ()
            cursor .execute ("SELECT MIN(timestamp) FROM events")
            result =cursor .fetchone ()
            return result [0 ]if result and result [0 ]else None
        except sqlite3.Error as e:
            logger.error(f"Failed to get earliest timestamp: {e}")
            report_exception(e, context="NOSPDatabase.get_earliest_timestamp")
            return None

    def get_latest_timestamp (self )->Optional [str ]:
        """Get the latest event timestamp"""
        try :
            cursor =self .conn .cursor ()
            cursor .execute ("SELECT MAX(timestamp) FROM events")
            result =cursor .fetchone ()
            return result [0 ]if result and result [0 ]else None
        except sqlite3.Error as e:
            logger.error(f"Failed to get latest timestamp: {e}")
            report_exception(e, context="NOSPDatabase.get_latest_timestamp")
            return None

    def get_events_before (self ,timestamp :str ,limit :int =50 )->List [Dict ]:
        """Get events before a specific timestamp"""
        try :
            cursor =self .conn .cursor ()
            cursor .execute ("""
                SELECT * FROM events 
                WHERE timestamp <= ?
                ORDER BY timestamp DESC 
                LIMIT ?
            """,(timestamp ,limit ))

            events =[]
            for row in cursor .fetchall ():
                events .append (dict (row ))

            return events
        except sqlite3.Error as e:
            logger.error(f"Failed to fetch historical events: {e}")
            report_exception(e, context="NOSPDatabase.get_events_before")
            return []

    @graceful()
    def insert_event_safe(self, event: Dict, risk_score: int, risk_factors: Optional[List[Tuple[str, int, str]]] = None) -> Result:
        return self.insert_event(event, risk_score, risk_factors)

    @graceful()
    def get_recent_events_safe(self, limit: int = 100, min_risk: int = 0) -> Result:
        return self.get_recent_events(limit, min_risk)

    @graceful()
    def update_ai_analysis_safe(self, event_id: int, analysis: str) -> Result:
        return self.update_ai_analysis(event_id, analysis)

    @graceful()
    def get_statistics_safe(self) -> Result:
        return self.get_statistics()

    @graceful()
    def log_status_safe(self, component: str, status: str, message: str = "") -> Result:
        return self.log_status(component, status, message)

    @graceful()
    def get_recent_network_events_safe(self, limit: int = 100) -> Result:
        return self.get_recent_network_events(limit)

    def close (self ):
        """Close database connection."""
        try :
            self .conn .close ()
            logger .info ("✓ Database connection closed")
        except sqlite3 .Error as e :
            logger .error (f"✗ Failed to close database: {e }")
            report_exception(e, context="NOSPDatabase.close")
            report_exception(e, context="NOSPDatabase.close")
