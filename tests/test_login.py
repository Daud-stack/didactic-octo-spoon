import pytest
from app import app, users, is_authenticated
from flask import session

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    with app.test_client() as client:
        yield client

def test_login_get(client):
    response = client.get('/login')
    assert response.status_code == 200
    # Add check for specific text in login.html if applicable, e.g., b"Login" in response.data

def test_login_post_valid_credentials(client):
    response = client.post('/login', data={
        'username': 'reviewer1',
        'password': 'password1'
    }, follow_redirects=True)
    assert response.status_code == 200

    # We should be redirected to index and have a username in session
    with client.session_transaction() as sess:
        assert sess['username'] == 'reviewer1'

def test_login_post_invalid_credentials(client):
    response = client.post('/login', data={
        'username': 'reviewer1',
        'password': 'wrongpassword'
    }, follow_redirects=True)
    assert response.status_code == 200

    # We should still be at login page (or get an error) and no session username
    assert b'Invalid credentials' in response.data
    with client.session_transaction() as sess:
        assert 'username' not in sess

def test_login_redirect_if_authenticated(client):
    with client.session_transaction() as sess:
        sess['username'] = 'reviewer1'
    response = client.get('/login', follow_redirects=False)
    assert response.status_code == 302
    assert response.headers['Location'] == '/index' or response.headers['Location'] == '/' or 'index' in response.headers['Location']
