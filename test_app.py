import pytest
from app import app, nonconformities

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test_secret_key'
    with app.test_client() as client:
        yield client

def test_add_nonconformity_unauthenticated(client):
    response = client.post('/add_nonconformity', data={
        'description': 'Test description',
        'severity': 'High'
    })
    # Should redirect to login
    assert response.status_code == 302
    assert '/login' in response.location

def test_add_nonconformity_authenticated(client):
    # Clear the global list before test
    nonconformities.clear()

    with client.session_transaction() as sess:
        sess['username'] = 'reviewer1'

    response = client.post('/add_nonconformity', data={
        'description': 'Test description',
        'severity': 'High'
    })

    # Check if we get 200 OK
    assert response.status_code == 200

    # Check if nonconformity was added
    assert len(nonconformities) == 1
    assert nonconformities[0]['description'] == 'Test description'
    assert nonconformities[0]['severity'] == 'High'

def test_add_nonconformity_empty_data(client):
    nonconformities.clear()

    with client.session_transaction() as sess:
        sess['username'] = 'reviewer1'

    response = client.post('/add_nonconformity', data={})

    # Check if we get 200 OK
    assert response.status_code == 200

    # Check if empty nonconformity was added (based on current implementation)
    assert len(nonconformities) == 1
    assert nonconformities[0]['description'] is None
    assert nonconformities[0]['severity'] is None
