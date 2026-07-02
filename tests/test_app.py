import unittest
from app import app, users

class AppTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()

    def test_login_success(self):
        response = self.client.post('/login', data={
            'username': 'reviewer1',
            'password': 'password1'
        })
        self.assertEqual(response.status_code, 302)
        self.assertIn('/index', response.headers.get('Location', '') or response.headers.get('Location'))

    def test_login_failure(self):
        response = self.client.post('/login', data={
            'username': 'reviewer1',
            'password': 'wrongpassword'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Invalid credentials', response.data)

if __name__ == '__main__':
    unittest.main()
