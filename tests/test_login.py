import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_login_invalid_credentials(client):
    response = client.post('/login', data={
        'username': 'wrong_user',
        'password': 'wrong_password'
    })

    assert response.status_code == 200
    assert b'Invalid credentials' in response.data
