import pytest
from app import app, documents, nonconformities

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@pytest.fixture(autouse=True)
def clear_state():
    documents.clear()
    nonconformities.clear()
    yield
    documents.clear()
    nonconformities.clear()

def test_approve_document_unauthenticated(client):
    response = client.post('/approve_document', data={'document_id': '1', 'action': 'Approve'})
    assert response.status_code == 302
    assert '/login' in response.headers['Location']

def test_approve_document_approve(client):
    documents.append({'id': 'doc1', 'status': 'Pending'})

    with client.session_transaction() as sess:
        sess['username'] = 'reviewer1'

    response = client.post('/approve_document', data={'document_id': 'doc1', 'action': 'Approve'})

    assert response.status_code == 302
    assert response.headers['Location'] == '/index'
    assert documents[0]['status'] == 'Approved'

def test_approve_document_reject(client):
    documents.append({'id': 'doc2', 'status': 'Pending'})

    with client.session_transaction() as sess:
        sess['username'] = 'reviewer1'

    response = client.post('/approve_document', data={'document_id': 'doc2', 'action': 'Reject'})

    assert response.status_code == 302
    assert response.headers['Location'] == '/index'
    assert documents[0]['status'] == 'Rejected'

def test_approve_document_not_found(client):
    with client.session_transaction() as sess:
        sess['username'] = 'reviewer1'

    response = client.post('/approve_document', data={'document_id': 'missing_doc', 'action': 'Approve'})

    assert response.status_code == 200
    # Should render index without altering missing doc
    assert len(documents) == 0
