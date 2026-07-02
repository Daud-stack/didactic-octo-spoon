import pytest
from app import app
from unittest.mock import patch, MagicMock

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@patch('app.Document', create=True)
def test_create_document_unauthenticated(mock_document, client):
    # Test that an unauthenticated user gets 401 Unauthorized
    response = client.post('/document', json={
        'id': 'doc1',
        'title': 'Test Doc',
        'content': 'Test Content',
        'version': '1.0'
    })
    assert response.status_code == 401
    assert response.get_json() == {'message': 'Unauthorized'}
    mock_document.assert_not_called()

@patch('app.Document', create=True)
def test_create_document_authenticated(mock_document, client):
    # Set up mock Document instance
    mock_doc_instance = MagicMock()
    mock_document.return_value = mock_doc_instance

    # Mock an authenticated session
    with client.session_transaction() as sess:
        sess['username'] = 'reviewer1'

    # Test that an authenticated user can create a document
    response = client.post('/document', json={
        'id': 'doc1',
        'title': 'Test Doc',
        'content': 'Test Content',
        'version': '1.0',
        'new_content': 'New Content'
    })

    assert response.status_code == 200
    assert response.get_json() == {'message': 'Document created successfully.'}

    # Verify Document was instantiated with correct args
    mock_document.assert_called_once_with('doc1', 'Test Doc', 'Test Content', '1.0')
    mock_doc_instance.approve.assert_called_once()
    mock_doc_instance.update_content.assert_called_once_with('New Content')
