from fastapi import FastAPI, HTTPException
import joblib
import json
import numpy as np
from pydantic import BaseModel
from tensorflow.keras.models import load_model
from contextlib import asynccontextmanager


# global variables for our models
scaler = None
xgb_model = None
autoencoder = None
ae_threshold = 0.0

# 2. Define the Input Data Schema
class NetworkTraffic(BaseModel):
    features: list[float]
    
    
# 3. Load models on startup
@asynccontextmanager
async def lifespan(app: FastAPI):
    global scaler, xgb_model, autoencoder, ae_threshold
    print('Initializing SOC Pipeline...')
    
    try:
        
        # load the preprocessing scaler
        scaler = joblib.load('../models/robust_scaler.pkl')
        if not scaler: print('No xgb')
        
        # load Stage 1: XGBoost Supervised Filter
        xgb_model = joblib.load('../models/xgboost_stage1.pkl')
        if not xgb_model: print('No xgb')
        
        # load stage 2: Keras Autoencoder
        autoencoder = load_model('../models/autoencoder_stage2.h5', compile=False)
        if not autoencoder: print('No autoencoder')
        
        # load the dynamic Threshold
        with open('../models/ae_threshold.json', 'r') as f:
            config = json.load(f)
            ae_threshold = config['best_threshold']
        
        print(f'Pipeline Ready. Autoencoder Threshold set to: {ae_threshold:.4f}')
    except Exception as e:
        print(f'Critical Error: Failed to load the models, {e}')
        raise RuntimeError(f'Startup aborted due to missing model files: {e}')
    
    yield
    # clean up the models and resources 
  
# 1. Initialize the FastAPI App
app = FastAPI(
    title='Next-Gen Hybrid SOC Pipeline',
    description='Two-Stage Intrusion Detection System: XGBoost + Deep Learning AutoEncoder',
    version="1.0",
    lifespan=lifespan
)

      
# 4. The Prediction endpoint
@app.post('/scan-traffic')
async def scan_network_traffic(traffic: NetworkTraffic):
    try:
        
        # convert incoming json list to a 2D numpy array: shape (1, features)
        raw_data = np.array(traffic.features).reshape(1,-1)
        
        # step 1: scale the raw data using the trained robustScaler
        scaled_data = scaler.transform(raw_data)
        
        # step 2: the front door XGBoost
        xgb_predictions = xgb_model.predict(scaled_data)[0]
        
        if xgb_predictions == 1:
            return {
                'action': 'Blocked',
                'threat_type': 'Known Attack',
                'caught_by': 'Stage 1 (XGBoost)',
                'details': 'Matches known malicious mathematical signature'
            }
        
        # step 3: The safety net autoencoder
        # if XGBoost says it's Benign (0), we double check it for zero-days
        reconstructions = autoencoder.predict(scaled_data, verbose=0)
        mae_error = np.mean(np.abs(scaled_data - reconstructions), axis=1)[0]
        
        if mae_error > ae_threshold:
            return {
                'action': 'Blocked',
                'threat_type': 'Potential Zero-day Anomaly',
                'caught_by': 'Stage 2 (Autoencoder)',
                'details': f'reconstruction error {mae_error:.4f} exceeded strict threshold ({ae_threshold:.4f})'
            }
        
        # stage 4: All clear
        return {
            'action': 'Allowed',
            'threat_type': 'None',
            'caught_by': 'Passed Both stages',
            'details': f'Normal traffic rhythm verified. Error: {mae_error:.4f}'        
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    

# Health check endpoint
@app.get('/')
async def root():
    return {'message': 'Hybrid SOC Pipeline is actively monitoring'}
    