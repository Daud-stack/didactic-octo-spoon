import unittest
from app import app

class AuthTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()

    def test_risk_assessment_unauthorized(self):
        response = self.app.post('/risk-assessment', json={'process': 'test', 'description': 'test', 'likelihood': 'low', 'impact': 'low'})
        self.assertEqual(response.status_code, 401)

if __name__ == '__main__':
    unittest.main()
