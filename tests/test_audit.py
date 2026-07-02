import pytest
from app import app
import unittest.mock as mock

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_perform_audit_success(client):
    with mock.patch('app.Audit', create=True) as mock_audit:
        response = client.post('/audit', json={
            'audit_date': '2023-09-01',
            'auditor': 'John Doe',
            'findings': ['Finding 1', 'Finding 2']
        })
        assert response.status_code == 200
        assert response.json == {'message': 'Audit performed successfully.'}

def test_perform_audit_missing_fields(client):
    with mock.patch('app.Audit', create=True) as mock_audit:
        response = client.post('/audit', json={
            'auditor': 'John Doe',
        })
        assert response.status_code == 400
        assert response.json == {'error': 'Missing required fields'}

def test_perform_audit_missing_json(client):
    with mock.patch('app.Audit', create=True) as mock_audit:
        response = client.post('/audit', data="not-json")
        assert response.status_code == 400
        assert response.json == {'error': 'Request must be JSON'}

def test_perform_audit_empty_findings(client):
    with mock.patch('app.Audit', create=True) as mock_audit:
        response = client.post('/audit', json={
            'audit_date': '2023-09-01',
            'auditor': 'John Doe',
            'findings': []
        })
        assert response.status_code == 200
        assert response.json == {'message': 'Audit performed successfully.'}
