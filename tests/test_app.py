import pytest
from app import app, is_authenticated
from flask import session

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test_secret_key'
    with app.test_client() as client:
        yield client

def test_is_authenticated_with_user(client):
    with client.session_transaction() as sess:
        sess['username'] = 'testuser'

    with app.test_request_context():
        # Setting session manually in test context
        session['username'] = 'testuser'
        assert is_authenticated() is True

def test_is_authenticated_without_user(client):
    with app.test_request_context():
        assert is_authenticated() is False

def test_is_authenticated_other_keys(client):
    with app.test_request_context():
        session['other_key'] = 'value'
        assert is_authenticated() is False
