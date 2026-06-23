import pytest
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test_secret'
    with app.test_client() as client:
        yield client

def test_index_unauthenticated(client):
    response = client.get('/index')
    assert response.status_code == 302
    assert '/login' in response.headers.get('Location', '')

def test_index_authenticated(client):
    with client.session_transaction() as sess:
        sess['username'] = 'reviewer1'

    response = client.get('/index')
    assert response.status_code == 200
    assert b'Nonconformity Tracking' in response.data or b'Document Review and Approval' in response.data
