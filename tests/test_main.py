import pytest
from fastapi.testclient import TestClient
from app.main import app

# We use a pytest fixture so that TestClient is used in a "with" block.
# This ensures that our FastAPI "lifespan" event runs and loads the models!
@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c

def test_health_check(client):
    '''Test 1: Does the server turn on and respond'''
    response = client.get('/')
    assert response.status_code == 200
    assert 'Hybrid SOC Pipeline' in response.json()['message']

def test_invalid_payload_shape(client):
    '''Test 2: Does the API block the wrong data like the array with only 3 numbers'''
    bad_payload = {
        "features": [0.0, 1.0, 2.0] # model needs 44
    }

    response = client.post('/scan-traffic', json=bad_payload)

    # it should return an HTTP error
    assert response.status_code != 200

def test_missing_payload(client):
    '''Test 3: Does the API handle completely empty requests?'''
    response = client.post('/scan-traffic', json={})
    # 422 Unprocessable Entity means FastAPI caught the missing data
    assert response.status_code == 422

def test_normal_traffic_simulation(client):
    '''Test 4: Does the AI Pipeline process a perfect array correctly?'''
    # creating an array of exactly 44 zeroes (simulating benign localhost traffic)
    normal_payload = {
        'features': [0.0] * 44
    }

    response = client.post('/scan-traffic', json=normal_payload)

    # DEBUG: Print the actual error if the API returns 500
    if response.status_code != 200:
        print(f"API Error: {response.json()}")

    assert response.status_code == 200

    result = response.json()

    # verifying the API returns the exact contract Streamlit is expecting
    assert 'action' in result
    assert 'threat_type' in result
    assert 'caught_by' in result
    assert 'details' in result

    # since its all zeroes, the AI should label it as normal
    assert result['action'] == 'ALLOWED'
