import pytest
from app import app, documents

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.secret_key = 'test_secret_key'
    with app.test_client() as client:
        yield client

@pytest.fixture(autouse=True)
def reset_documents():
    # Clear the global list before and after each test
    documents.clear()
    yield
    documents.clear()

def test_approve_document_unauthenticated(client):
    response = client.post('/approve_document', data={'document_id': '1', 'action': 'Approve'})
    assert response.status_code == 302
    assert '/login' in response.headers['Location']

def test_approve_document_approve(client):
    # Pre-populate global documents
    documents.append({'id': '1', 'status': 'Pending'})

    with client.session_transaction() as sess:
        sess['username'] = 'testuser'

    response = client.post('/approve_document', data={'document_id': '1', 'action': 'Approve'})

    # Assert redirect to index
    assert response.status_code == 302
    assert '/' in response.headers['Location']

    # Assert status update
    assert documents[0]['status'] == 'Approved'

def test_approve_document_reject(client):
    documents.append({'id': '2', 'status': 'Pending'})

    with client.session_transaction() as sess:
        sess['username'] = 'testuser'

    response = client.post('/approve_document', data={'document_id': '2', 'action': 'Reject'})

    assert response.status_code == 302
    assert '/' in response.headers['Location']
    assert documents[0]['status'] == 'Rejected'

def test_approve_document_not_found(client):
    with client.session_transaction() as sess:
        sess['username'] = 'testuser'

    response = client.post('/approve_document', data={'document_id': '999', 'action': 'Approve'})

    # Assert fallback to rendering index.html
    assert response.status_code == 200
    assert b'nonconformities' in response.data or b'documents' in response.data or b'html' in response.data # check template response
