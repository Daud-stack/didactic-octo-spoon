import pytest
from unittest.mock import patch
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_analysis_unauthenticated(client):
    response = client.post('/analysis', json={'data': 'test_data'})
    assert response.status_code == 401
    assert response.get_json() == {'message': 'Unauthorized'}

@patch('app.Analysis', create=True)
def test_analysis_authenticated(mock_analysis_class, client):
    # Setup mock
    mock_instance = mock_analysis_class.return_value
    mock_instance.analyze_data.return_value = {'result': 'success'}

    # Setup authenticated session
    with client.session_transaction() as sess:
        sess['username'] = 'reviewer1'

    response = client.post('/analysis', json={'data': 'test_data'})

    assert response.status_code == 200
    assert response.get_json() == {'result': 'success'}
    mock_analysis_class.assert_called_once_with(data='test_data')
    mock_instance.analyze_data.assert_called_once()
