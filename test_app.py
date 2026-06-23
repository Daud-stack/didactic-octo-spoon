from app import app
import unittest

class AppTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_index_unauthenticated(self):
        result = self.app.get('/index')
        self.assertEqual(result.status_code, 302)

    def test_index_authenticated(self):
        with self.app.session_transaction() as sess:
            sess['username'] = 'reviewer1'
        result = self.app.get('/index')
        self.assertEqual(result.status_code, 200)
        self.assertIn(b'Nonconformity Tracking', result.data)
        self.assertIn(b'Document Review and Approval', result.data)

if __name__ == '__main__':
    unittest.main()
