import pytest
from unittest.mock import patch, MagicMock
from app import app, nonconformities, documents

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@pytest.fixture(autouse=True)
def clear_state():
    nonconformities.clear()
    documents.clear()
    yield

@patch('app.RiskAssessment', create=True)
def test_risk_assessment_unauthenticated(mock_risk_assessment, client):
    response = client.post('/risk-assessment', json={
        'process': 'Test Process',
        'description': 'Test Description',
        'likelihood': 3,
        'impact': 4
    })
    assert response.status_code == 401
    assert response.json == {'message': 'Unauthorized'}
    mock_risk_assessment.assert_not_called()

@patch('app.RiskAssessment', create=True)
def test_risk_assessment_authenticated(mock_risk_assessment_class, client):
    mock_instance = MagicMock()
    mock_instance.calculate_risk_level.return_value = 'High'
    mock_risk_assessment_class.return_value = mock_instance

    with client.session_transaction() as sess:
        sess['username'] = 'reviewer1'

    response = client.post('/risk-assessment', json={
        'process': 'Test Process',
        'description': 'Test Description',
        'likelihood': 3,
        'impact': 4
    })

    assert response.status_code == 200
    assert response.json == {'risk_level': 'High'}
    mock_risk_assessment_class.assert_called_once_with(
        process='Test Process',
        description='Test Description',
        likelihood=3,
        impact=4
    )
    mock_instance.calculate_risk_level.assert_called_once()
