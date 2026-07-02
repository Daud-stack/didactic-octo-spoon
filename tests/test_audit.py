import pytest
from unittest.mock import patch
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_audit_unauthenticated(client):
    response = client.post('/audit', json={
        "audit_date": "2023-09-01",
        "auditor": "John Doe",
        "findings": ["Finding 1", "Finding 2"]
    })
    assert response.status_code == 401
    assert response.json == {"message": "Unauthorized"}

@patch('app.Audit', create=True)
def test_audit_authenticated(mock_audit, client):
    # Mocking authenticated session
    with client.session_transaction() as sess:
        sess['username'] = 'reviewer1'

    mock_instance = mock_audit.return_value
    mock_instance.add_finding.return_value = None
    mock_instance.print_report.return_value = None

    response = client.post('/audit', json={
        "audit_date": "2023-09-01",
        "auditor": "John Doe",
        "findings": ["Finding 1", "Finding 2"]
    })
    assert response.status_code == 200
    assert response.json == {"message": "Audit performed successfully."}

    # Check that Audit was called with proper args
    mock_audit.assert_called_once_with(
        audit_date="2023-09-01",
        auditor="John Doe",
        findings=["Finding 1", "Finding 2"]
    )
    mock_instance.add_finding.assert_called_once_with('Additional finding')
    mock_instance.print_report.assert_called_once()
