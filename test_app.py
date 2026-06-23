import pytest
from app import app, nonconformities

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test_secret_key'
    with app.test_client() as client:
        yield client

def test_add_nonconformity_success(client):
    nonconformities.clear()
    with client.session_transaction() as sess:
        sess['username'] = 'reviewer1'

    response = client.post('/add_nonconformity', data={
        'description': 'Test Description',
        'severity': 'High'
    })

    assert response.status_code == 302
    assert '/index' in response.location
    assert len(nonconformities) == 1
    assert nonconformities[0]['description'] == 'Test Description'
    assert nonconformities[0]['severity'] == 'High'

def test_add_nonconformity_unauthenticated(client):
    nonconformities.clear()
    response = client.post('/add_nonconformity', data={
        'description': 'Test Description',
        'severity': 'High'
    })

    assert response.status_code == 302
    assert '/login' in response.location
    assert len(nonconformities) == 0

def test_add_nonconformity_missing_description(client):
    nonconformities.clear()
    with client.session_transaction() as sess:
        sess['username'] = 'reviewer1'

    response = client.post('/add_nonconformity', data={
        'severity': 'High'
    })

    # Depending on what the expected behavior is, we assert here.
    # The current code accepts it and adds `None` for description!
    assert response.status_code == 302
    assert len(nonconformities) == 1
    assert nonconformities[0]['description'] is None
    assert nonconformities[0]['severity'] == 'High'

def test_add_nonconformity_missing_severity(client):
    nonconformities.clear()
    with client.session_transaction() as sess:
        sess['username'] = 'reviewer1'

    response = client.post('/add_nonconformity', data={
        'description': 'Test Description'
    })

    assert response.status_code == 302
    assert len(nonconformities) == 1
    assert nonconformities[0]['description'] == 'Test Description'
    assert nonconformities[0]['severity'] is None
