from fastapi import FastAPI
import joblib
import numpy as np
from pydantic import BaseModel


app = FastAPI()

# load model and scaler
model = joblib.load('../models/isolation_model.pkl')
scaler = joblib.load('../models/scaler.pkl')

class NetworkFlow(BaseModel):
    flow_duration: float
    Header_Length: float
    Protocol_Type: int  # Note: Pydantic model names can't have spaces
    Duration: float
    Rate: float
    Drate: float
    fin_flag_number: float
    syn_flag_number: float
    psh_flag_number: float
    ack_flag_number: float
    syn_count: float
    fin_count: float
    urg_count: float
    rst_count: float
    HTTP: float
    HTTPS: float
    DNS: float
    SSH: float
    TCP: float
    UDP: float
    ARP: float
    ICMP: float
    IPv: float
    Tot_sum: float
    Min: float
    Max: float
    AVG: float
    Tot_size: float
    IAT: float
    Covariance: float
    Variance: float
    

Feature_Names  = [
    'flow_duration', 'Header_Length', 'Protocol Type', 'Duration', 'Rate',
       'Drate', 'fin_flag_number', 'syn_flag_number', 'psh_flag_number',
       'ack_flag_number', 'syn_count', 'fin_count', 'urg_count', 'rst_count',
       'HTTP', 'HTTPS', 'DNS', 'SSH', 'TCP', 'UDP', 'ARP', 'ICMP', 'IPv',
       'Tot sum', 'Min', 'Max', 'AVG', 'Tot size', 'IAT', 'Covariance',
       'Variance'
]

@app.get('/')
def home():
    return {'message': 'Zero Day Attack Detection API runing'}

@app.post('/detect')
def detect(flow: NetworkFlow):
    
    #convert python model to a dictionary, then to an ordered list
    flow_dict = flow.dict()
    print(flow_dict)
    
    # manually handle the keys with spaces
    flow_dict['Protocol Type'] = flow_dict.pop('Protocol_Type')
    flow_dict['Tot sum'] = flow_dict.pop('Tot_sum')
    flow_dict['Tot size'] = flow_dict.pop('Tot_size')
    
    x = [flow_dict[col] for col in Feature_Names]
    print('\n',x)
    
    #scale input
    x_scaled = scaler.transform([x])
    
    # get anomaly score
    score = -model.score_samples(x_scaled)[0]
    
    #threshold 
    threshold = 0.5
    
    alert = score > threshold
    
    return {
        "anomaly_score": float(score),
        "alert": bool(alert),
        "risk_level": "High" if score > 0.7 else "MEDIUM" if score > 0.5 else "LOW"
    }