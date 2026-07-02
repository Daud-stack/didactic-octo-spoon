import pytest
from app import app, nonconformities, documents

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False

    with app.test_client() as client:
        with app.app_context():
            # Reset global variables before each test
            nonconformities.clear()
            documents.clear()
        yield client

def test_hello_qms(client):
    response = client.get('/')
    assert response.status_code == 200

def test_index_unauthenticated(client):
    response = client.get('/index')
    assert response.status_code == 302
    assert '/login' in response.headers['Location']

def test_index_authenticated(client):
    with client.session_transaction() as sess:
        sess['username'] = 'reviewer1'
    response = client.get('/index')
    assert response.status_code == 200

def test_login_valid(client):
    response = client.post('/login', data={'username': 'reviewer1', 'password': 'password1'})
    assert response.status_code == 302
    assert '/index' in response.headers['Location']
    with client.session_transaction() as sess:
        assert sess['username'] == 'reviewer1'

def test_login_invalid(client):
    response = client.post('/login', data={'username': 'reviewer1', 'password': 'wrongpassword'})
    assert response.status_code == 200
    assert b'Invalid credentials' in response.data
    with client.session_transaction() as sess:
        assert 'username' not in sess

def test_logout(client):
    with client.session_transaction() as sess:
        sess['username'] = 'reviewer1'
    response = client.get('/logout')
    assert response.status_code == 302
    assert '/login' in response.headers['Location']
    with client.session_transaction() as sess:
        assert 'username' not in sess

def test_add_nonconformity(client):
    with client.session_transaction() as sess:
        sess['username'] = 'reviewer1'
    response = client.post('/add_nonconformity', data={'description': 'Test NC', 'severity': 'High'})
    assert response.status_code == 302
    assert '/index' in response.headers['Location']
    assert len(nonconformities) == 1
    assert nonconformities[0]['description'] == 'Test NC'
    assert nonconformities[0]['severity'] == 'High'

def test_add_nonconformity_unauthenticated(client):
    response = client.post('/add_nonconformity', data={'description': 'Test NC', 'severity': 'High'})
    assert response.status_code == 302
    assert '/login' in response.headers['Location']
    assert len(nonconformities) == 0

def test_approve_document(client):
    documents.append({'id': 'doc1', 'status': 'Pending'})
    with client.session_transaction() as sess:
        sess['username'] = 'reviewer1'
    response = client.post('/approve_document', data={'document_id': 'doc1', 'action': 'Approve'})
    assert response.status_code == 302
    assert '/index' in response.headers['Location']
    assert documents[0]['status'] == 'Approved'

def test_reject_document(client):
    documents.append({'id': 'doc2', 'status': 'Pending'})
    with client.session_transaction() as sess:
        sess['username'] = 'reviewer1'
    response = client.post('/approve_document', data={'document_id': 'doc2', 'action': 'Reject'})
    assert response.status_code == 302
    assert '/index' in response.headers['Location']
    assert documents[0]['status'] == 'Rejected'

def test_approve_document_unauthenticated(client):
    documents.append({'id': 'doc3', 'status': 'Pending'})
    response = client.post('/approve_document', data={'document_id': 'doc3', 'action': 'Approve'})
    assert response.status_code == 302
    assert '/login' in response.headers['Location']
    assert documents[0]['status'] == 'Pending'

from unittest.mock import patch

@patch('app.Audit', create=True)
def test_perform_audit(mock_audit, client):
    response = client.post('/audit', json={
        'audit_date': '2023-09-01',
        'auditor': 'John Doe',
        'findings': ['Finding 1', 'Finding 2']
    })
    assert response.status_code == 200
    assert response.get_json()['message'] == 'Audit performed successfully.'
    mock_audit.assert_called_once()
    mock_audit.return_value.add_finding.assert_called_with('Additional finding')
    mock_audit.return_value.print_report.assert_called_once()

@patch('app.RiskAssessment', create=True)
def test_perform_risk_assessment(mock_risk_assessment, client):
    mock_risk_assessment.return_value.calculate_risk_level.return_value = 'High'
    response = client.post('/risk-assessment', json={
        'process': 'Manufacturing',
        'description': 'Equipment failure',
        'likelihood': 4,
        'impact': 5
    })
    assert response.status_code == 200
    assert response.get_json()['risk_level'] == 'High'
    mock_risk_assessment.assert_called_once()

@patch('app.Analysis', create=True)
def test_perform_analysis(mock_analysis, client):
    mock_analysis.return_value.analyze_data.return_value = {'result': 'success'}
    response = client.post('/analysis', json={
        'data': [1, 2, 3]
    })
    assert response.status_code == 200
    assert response.get_json() == {'result': 'success'}
    mock_analysis.assert_called_once()

@patch('app.NonConformity', create=True)
def test_create_non_conformity(mock_non_conformity, client):
    response = client.post('/non-conformity', json={
        'id': 'nc1',
        'description': 'Test description',
        'impact': 'High',
        'assignee': 'reviewer1'
    })
    assert response.status_code == 200
    assert response.get_json()['message'] == 'Non-conformity created successfully.'
    mock_non_conformity.assert_called_once()
    mock_non_conformity.return_value.assign.assert_called_with('reviewer1')
    mock_non_conformity.return_value.close.assert_called_once()

@patch('app.Document', create=True)
def test_create_document(mock_document, client):
    response = client.post('/document', json={
        'id': 'doc1',
        'title': 'Test Doc',
        'content': 'Initial content',
        'version': '1.0',
        'new_content': 'Updated content'
    })
    assert response.status_code == 200
    assert response.get_json()['message'] == 'Document created successfully.'
    mock_document.assert_called_once()
    mock_document.return_value.approve.assert_called_once()
    mock_document.return_value.update_content.assert_called_with('Updated content')

@patch('app.ComplianceItem', create=True)
def test_update_compliance(mock_compliance_item, client):
    response = client.post('/compliance', json={
        'id': 'comp1',
        'name': 'Test Rule',
        'description': 'Rule description',
        'status': 'Pending',
        'new_status': 'Compliant'
    })
    assert response.status_code == 200
    assert response.get_json()['message'] == 'Compliance item updated successfully.'
    mock_compliance_item.assert_called_once()
    mock_compliance_item.return_value.update_status.assert_called_with('Compliant')

@patch('app.CorrectiveAction', create=True)
def test_complete_corrective_action(mock_corrective_action, client):
    response = client.post('/corrective-action', json={
        'id': 'ca1',
        'description': 'Fix the issue',
        'due_date': '2023-10-01',
        'assigned_to': 'reviewer1'
    })
    assert response.status_code == 200
    assert response.get_json()['message'] == 'Corrective action completed successfully.'
    mock_corrective_action.assert_called_once()
    mock_corrective_action.return_value.complete.assert_called_once()
