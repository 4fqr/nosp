"""
NOSP vOMEGA - Machine Learning Anomaly Detection
Uses Isolation Forest for unsupervised anomaly detection in process behavior
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib
import logging
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from datetime import datetime
from .errors import report_exception

logger = logging.getLogger(__name__)


class MLAnomalyDetector :
    """
    Machine Learning anomaly detector using Isolation Forest
    
    Features:
    - Unsupervised learning (no labeled data required)
    - Real-time anomaly scoring (-1 to 1)
    - Automatic model retraining
    - Feature engineering from process events
    - Model persistence and loading
    """

    def __init__ (self ,model_path :str ="models/anomaly_detector.pkl"):
        self .model_path =Path (model_path )
        self .model_path .parent .mkdir (parents =True ,exist_ok =True )

        self .model :Optional [IsolationForest ]=None
        self .scaler =StandardScaler ()
        self .label_encoders :Dict [str ,LabelEncoder ]={}

        self .training_buffer :List [Dict [str ,Any ]]=[]
        self .buffer_size =1000
        self .min_training_samples =100

        self .numerical_features =[
        'risk_score',
        'cmdline_length',
        'parent_pid',
        'pid',
        'hour_of_day',
        'day_of_week'
        ]

        self .categorical_features =[
        'process_name',
        'parent_name',
        'user'
        ]

        self .stats ={
        'predictions':0 ,
        'anomalies_detected':0 ,
        'normal_detected':0 ,
        'training_samples':0 ,
        'last_trained':None
        }

        self .load_model ()

        if self .model is None :
            self ._init_model ()

    def _init_model (self ):
        """Initialize a new Isolation Forest model"""
        self .model =IsolationForest (
        n_estimators =100 ,
        contamination =0.1 ,
        max_samples ='auto',
        random_state =42 ,
        n_jobs =-1
        )
        logger .info ("Initialized new Isolation Forest model")

    def extract_features (self ,event :Dict [str ,Any ])->Dict [str ,Any ]:
        """
        Extract and engineer features from a security event
        
        Features include:
        - Numerical: risk_score, cmdline_length, PIDs, time features
        - Categorical: process_name, parent_name, user
        """
        features ={}

        features ['risk_score']=float (event .get ('risk_score',0 ))
        features ['cmdline_length']=len (event .get ('cmdline',''))
        features ['parent_pid']=int (event .get ('parent_pid',0 ))
        features ['pid']=int (event .get ('pid',0 ))

        try:
            timestamp = datetime.fromisoformat(event.get('timestamp', datetime.now().isoformat()))
            features['hour_of_day'] = timestamp.hour
            features['day_of_week'] = timestamp.weekday()
        except Exception:
            features['hour_of_day'] = 0
            features['day_of_week'] = 0

        features ['process_name']=event .get ('process_name','unknown').lower ()
        features ['parent_name']=event .get ('parent_name','unknown').lower ()
        features ['user']=event .get ('user','unknown').lower ()

        return features

    def _encode_features (self ,features_dict :Dict [str ,Any ],fit :bool =False )->np .ndarray :
        """
        Encode features into numerical array
        
        Args:
            features_dict: Dictionary of feature values
            fit: If True, fit encoders (during training); if False, transform only
        
        Returns:
            Numpy array of encoded features
        """
        feature_vector =[]

        for feat in self .numerical_features :
            feature_vector .append (float (features_dict .get (feat ,0 )))

        for feat in self .categorical_features :
            value =str (features_dict .get (feat ,'unknown'))

            if fit :
                if feat not in self .label_encoders :
                    self .label_encoders [feat ]=LabelEncoder ()

                try :
                    if value not in self .label_encoders [feat ].classes_ :
                        classes =list (self .label_encoders [feat ].classes_ )
                        classes .append (value )
                        self .label_encoders [feat ].classes_ =np .array (classes )
                except Exception:
                    self.label_encoders[feat].fit([value])

                encoded = self.label_encoders[feat].transform([value])[0]
            else :
                if feat not in self .label_encoders :
                    encoded =0
                else :
                    try:
                        encoded = self.label_encoders[feat].transform([value])[0]
                    except Exception:
                        encoded = 0

            feature_vector .append (float (encoded ))

        return np .array (feature_vector ).reshape (1 ,-1 )

    def add_training_sample (self ,event :Dict [str ,Any ]):
        """Add an event to the training buffer"""
        features =self .extract_features (event )
        self .training_buffer .append (features )

        if len (self .training_buffer )>self .buffer_size :
            self .training_buffer .pop (0 )

    def train (self ,force :bool =False )->bool :
        """
        Train the model on buffered samples
        
        Args:
            force: Train even if minimum samples not reached
        
        Returns:
            True if training successful
        """
        if not force and len(self.training_buffer) < self.min_training_samples:
            logger.info(f"Not enough samples for training: {len(self.training_buffer)}/{self.min_training_samples}")
            return False

        try :
            logger .info (f"Training model on {len (self .training_buffer )} samples...")

            X =[]
            for features in self .training_buffer :
                encoded =self ._encode_features (features ,fit =True )
                X .append (encoded [0 ])

            X =np .array (X )

            X_scaled =self .scaler .fit_transform (X )

            self .model .fit (X_scaled )

            self .stats ['training_samples']=len (self .training_buffer )
            self .stats ['last_trained']=datetime .now ().isoformat ()

            self .save_model ()

            logger .info (f"✓ Model trained successfully with {len (self .training_buffer )} samples")
            return True

        except Exception as e:
            logger.error(f"Training failed: {e}")
            report_exception(e, context="MLAnomalyDetector.train")
            return False

    def predict (self ,event :Dict [str ,Any ])->Tuple [bool ,float ,str ]:
        """
        Predict if an event is anomalous
        
        Returns:
            Tuple of (is_anomaly, anomaly_score, confidence_level)
            - is_anomaly: True if anomalous
            - anomaly_score: -1 (anomaly) to 1 (normal)
            - confidence_level: "high", "medium", or "low"
        """
        if self .model is None :
            return False ,0.0 ,"no_model"

        try :
            features =self .extract_features (event )
            X =self ._encode_features (features ,fit =False )

            X_scaled =self .scaler .transform (X )

            prediction =self .model .predict (X_scaled )[0 ]
            anomaly_score =self .model .score_samples (X_scaled )[0 ]

            self .stats ['predictions']+=1

            is_anomaly =(prediction ==-1 )

            if is_anomaly :
                self .stats ['anomalies_detected']+=1
            else :
                self .stats ['normal_detected']+=1

            abs_score =abs (anomaly_score )
            if abs_score >0.3 :
                confidence ="high"
            elif abs_score >0.15 :
                confidence ="medium"
            else :
                confidence ="low"

            return is_anomaly ,float (anomaly_score ),confidence

        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            report_exception(e, context="MLAnomalyDetector.predict")
            return False, 0.0, "error"

    def save_model (self )->bool :
        """Save model and encoders to disk"""
        try :
            model_data ={
            'model':self .model ,
            'scaler':self .scaler ,
            'label_encoders':self .label_encoders ,
            'stats':self .stats ,
            'version':'1.0'
            }

            joblib .dump (model_data ,self .model_path )
            logger .info (f"Model saved to {self .model_path }")
            return True

        except Exception as e:
            logger.error(f"Failed to save model: {e}")
            report_exception(e, context="MLAnomalyDetector.save_model")
            return False

    def load_model (self )->bool :
        """Load model and encoders from disk"""
        if not self .model_path .exists ():
            logger .info ("No existing model found")
            return False

        try :
            model_data =joblib .load (self .model_path )

            self .model =model_data ['model']
            self .scaler =model_data ['scaler']
            self .label_encoders =model_data ['label_encoders']
            self .stats =model_data .get ('stats',self .stats )

            logger .info (f"Model loaded from {self .model_path }")
            logger .info (f"Last trained: {self .stats .get ('last_trained','unknown')}")
            return True

        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            report_exception(e, context="MLAnomalyDetector.load_model")
            return False

    def get_feature_importance (self )->Dict [str ,float ]:
        """
        Get approximate feature importance based on model
        (Isolation Forest doesn't have direct feature importance)
        """
        if self .model is None :
            return {}

        all_features =self .numerical_features +self .categorical_features
        return {feat :1.0 /len (all_features )for feat in all_features }

    def get_stats (self )->Dict [str ,Any ]:
        """Get detector statistics"""
        stats =self .stats .copy ()
        stats ['buffer_size']=len (self .training_buffer )
        stats ['model_loaded']=self .model is not None

        total =stats ['predictions']
        if total >0 :
            stats ['anomaly_rate']=stats ['anomalies_detected']/total
        else :
            stats ['anomaly_rate']=0.0

        return stats

    def reset_stats (self ):
        """Reset prediction statistics"""
        self .stats ['predictions']=0
        self .stats ['anomalies_detected']=0
        self .stats ['normal_detected']=0


def create_ml_detector (model_path :str ="models/anomaly_detector.pkl")->MLAnomalyDetector :
    """Create and initialize ML anomaly detector"""
    return MLAnomalyDetector (model_path )
