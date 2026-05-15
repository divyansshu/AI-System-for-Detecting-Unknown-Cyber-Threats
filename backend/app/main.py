import warnings
warnings.filterwarnings('ignore')

from fastapi import FastAPI, HTTPException
import joblib
import json
import numpy as np
import pandas as pd
from pathlib import Path
from pydantic import BaseModel, Field
from tensorflow.keras.models import load_model
from contextlib import asynccontextmanager
from sqlalchemy.orm import Session
from fastapi import Depends
from db.database import engine, get_db, Base
from db.models import ThreatAlert
import asyncio
from aiokafka import AIOKafkaConsumer
import logging
import os
from dotenv import load_dotenv

load_dotenv()

# configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# __file__ = backend/app/main.py → .parent.parent = backend/ → .parent = project root
MODEL_DIR = Path(__file__).resolve().parent.parent.parent / "models"

TOPIC = os.getenv("KAFKA_TOPIC")
KAFKA_SERVER = os.getenv("KAFKA_BOOTSTRAP_SERVERS")

# global variables for our models
scaler = None
xgb_model = None
autoencoder = None
ae_threshold = 0.0

# 2. Define the Input Data Schema
class NetworkTraffic(BaseModel):
    features: list[float] = Field(..., min_length=44, max_length=44,
        description='Must contain exactly 44 float dtype network flow features' )

def evaluate_network_flow(features_list: list[float],db:Session):

    #1. validation phase
    # even though fastapi validates Http requests, kafka might send bad data.
    if not isinstance(features_list, list) or len(features_list) != 44:
        logger.error(f'Validation Error: Expected 44 features, got {len(features_list) if isinstance(features_list, list) else type(features_list)}')
        raise ValueError('Invalid feature list length. Expected exactly 44 features.')

    # 2. Machine learning phase
    try:
        feature_names = getattr(scaler, "feature_names_in_", None)
        if feature_names is not None:
            raw_data = pd.DataFrame([features_list], columns=feature_names)
        else:
            raw_data = np.array(features_list).reshape(1, -1)

        # step 1: scale the raw data using the trained robustScaler
        scaled_data = scaler.transform(raw_data)

        # stage 1: the front door XGBoost
        xgb_predictions = xgb_model.predict(scaled_data)[0]

        if xgb_predictions == 1:
            action = 'BLOCKED'
            threat_type = 'Known Attack'
            caught_by = 'Stage 1 (XGBoost)'
            details = 'Matches known malicious mathematical signature'
            score = 0.99  # dummy high score for db since xgboost doesn't output mae

        else:
            # stage 2: The safety net autoencoder
            # if XGBoost says it's Benign (0), double check it for zero-days
            reconstructions = autoencoder.predict(scaled_data, verbose=0)
            mae_error = np.mean(np.abs(scaled_data - reconstructions), axis=1)[0]
            score = float(mae_error)

            if mae_error > ae_threshold:
                action = 'BLOCKED'
                threat_type = 'Potential Zero-day Anomaly'
                caught_by = 'Stage 2 (Autoencoder)'
                details = f'reconstruction error {mae_error:.4f} exceeded strict threshold ({ae_threshold:.4f})'
            else:
                action = 'ALLOWED'
                threat_type = 'None'
                caught_by = 'Passed Both Stages'
                details = f'Normal Traffic rhythm verified. Error: {mae_error:.4f}'

    except Exception as e:
        # logs the full stack trace of why the math failed
        logger.exception('ML Model Inference failed.')
        raise RuntimeError(f'Ml Processing Error: {str(e)}') from e

    # 3. Database phase
    try:
        # 1. create a new python object matching our table schema
        new_alert = ThreatAlert(
                action=action,
                threat_type=threat_type,
                caught_by=caught_by,
                anomaly_score=float(score)
        )
        # 2. Stage the object to be saved
        db.add(new_alert)
        # 3. commit it permanently to the postgreSQL
        db.commit()
        # refresh to ensure it saved correctly
        db.refresh(new_alert)

    except Exception as e:
       # logs the full stack trace of why PostgreSQL rejected the save
       logger.exception('Database Save Error.')
       db.rollback()
       raise ConnectionError('Failed to save threat to the database.') from e


    return {
        'action': action,
        'threat_type': threat_type,
        'caught_by': caught_by,
        'details': details
    }

async def consume_kafka_traffic():
    """This background function listens to kafka continuously"""
    consumer = AIOKafkaConsumer(
        TOPIC,
        bootstrap_servers=KAFKA_SERVER,
        value_deserializer=lambda m: json.loads(m.decode('utf-8'))
    )
    await consumer.start()
    logger.info('Kafka Consumer started listening...')
    try:
        async for msg in consumer:
            traffic_payload = msg.value
            features = traffic_payload.get('features')

            if features:
                # open a dedicated database for this background thread
                with Session(engine) as db:
                    try:
                        evaluate_network_flow(features, db)
                    except Exception:
                        logger.warning('Dropped invalid or failed kafka packet. Continuing..')

    except Exception as e:
        logger.exception('Fatal Kafka Consumer Error.')
    finally:
        await consumer.stop()
        logger.info('Kafka Consumer stopped.')

# 3. Load models on startup
@asynccontextmanager
async def lifespan(app: FastAPI):
    global scaler, xgb_model, autoencoder, ae_threshold
    print('Initializing SOC Pipeline...')
    
    try:
        print(f'connecting to postgresql and verifying tables...')
        Base.metadata.create_all(bind=engine)
        print('database tables verified successfully..')
        
        # load the preprocessing scaler
        scaler = joblib.load(MODEL_DIR / 'robust_scaler.pkl')
        
        # load Stage 1: XGBoost Supervised Filter
        xgb_model = joblib.load(MODEL_DIR / 'xgboost_stage1.pkl')
        
        # load stage 2: Keras Autoencoder
        autoencoder = load_model(MODEL_DIR / 'autoencoder_stage2.h5', compile=False)
        
        # load the dynamic Threshold
        with open(MODEL_DIR / 'ae_threshold.json', 'r') as f:
            config = json.load(f)
            ae_threshold = config['best_threshold']
        
        print(f'Pipeline Ready. Autoencoder Threshold set to: {ae_threshold:.4f}')
    except Exception as e:
        print(f'Critical Error: Failed to load the models, {e}')
        raise RuntimeError(f'Startup aborted due to missing model files: {e}')

    # spin up the kafka consumer as a background asyncio task
    kafka_task = asyncio.create_task(consume_kafka_traffic())
    
    yield
    # clean up the models and resources
    kafka_task.cancel()
  
# 1. Initialize the FastAPI App
app = FastAPI(
    title='Next-Gen Hybrid SOC Pipeline',
    description='Two-Stage Intrusion Detection System: XGBoost + Deep Learning AutoEncoder',
    version="1.0",
    lifespan=lifespan
)

# 4. The Prediction endpoint
@app.post('/scan-traffic')
async def scan_network_traffic(traffic: NetworkTraffic, db:Session = Depends(get_db)):
    """Manual fallback endpoint for UI Integration and testing"""
    try:
        result = evaluate_network_flow(traffic.features, db)
        return result
    except ValueError as ve:
        # 422 Unprocessable Entity
        raise HTTPException(status_code=422, detail=str(ve))
    except RuntimeError as re:
        # 500 Internal Server Error (Math/Model Failure)
        raise HTTPException(status_code=500, detail='Internal ML processing error.')
    except ConnectionError as ce:
        # 503 Service Unavailable (Database Failure)
        raise HTTPException(status_code=503, detail='Database Connection Failed.')


# Health check endpoint
@app.get('/')
async def root():
    return {'message': 'Hybrid SOC Pipeline is actively monitoring'}
    
