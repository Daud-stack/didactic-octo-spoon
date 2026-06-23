import pytest
from app import app
from unittest.mock import patch

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@patch('app.NonConformity', create=True)
def test_create_non_conformity_success(mock_nc, client):
    mock_instance = mock_nc.return_value
    mock_instance.assign.return_value = None
    mock_instance.close.return_value = None

    response = client.post('/non-conformity', json={
        'id': 1,
        'description': 'test description',
        'impact': 'high',
        'assignee': 'John Doe'
    })

    assert response.status_code == 200
    assert response.get_json() == {'message': 'Non-conformity created successfully.'}
    mock_nc.assert_called_once_with(1, 'test description', 'high')
    mock_instance.assign.assert_called_once_with('John Doe')
    mock_instance.close.assert_called_once()

@patch('app.NonConformity', create=True)
def test_create_non_conformity_missing_fields(mock_nc, client):
    response = client.post('/non-conformity', json={'id': 1})
    assert response.status_code == 400

@patch('app.NonConformity', create=True)
def test_create_non_conformity_bad_json(mock_nc, client):
    response = client.post('/non-conformity', data="not json")
    assert response.status_code == 400

@patch('app.NonConformity', create=True)
def test_create_non_conformity_exception(mock_nc, client):
    mock_nc.side_effect = Exception("Simulated exception")

    response = client.post('/non-conformity', json={
        'id': 1,
        'description': 'test description',
        'impact': 'high',
        'assignee': 'John Doe'
    })

    assert response.status_code == 500
    assert response.get_json() == {'error': 'Simulated exception'}
