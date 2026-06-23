import unittest
from app import app

class AuthTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()

    def test_audit_unauthorized(self):
        response = self.app.post('/audit', json={'audit_date': '2023-01-01', 'auditor': 'test', 'findings': []})
        self.assertEqual(response.status_code, 401)

    def test_analysis_unauthorized(self):
        response = self.app.post('/analysis', json={'data': 'test'})
        self.assertEqual(response.status_code, 401)

    def test_non_conformity_unauthorized(self):
        response = self.app.post('/non-conformity', json={'id': 1, 'description': 'test', 'impact': 'low'})
        self.assertEqual(response.status_code, 401)

    def test_document_unauthorized(self):
        response = self.app.post('/document', json={'id': 1, 'title': 'test', 'content': 'test', 'version': '1.0'})
        self.assertEqual(response.status_code, 401)

    def test_compliance_unauthorized(self):
        response = self.app.post('/compliance', json={'id': 1, 'name': 'test', 'description': 'test', 'status': 'open'})
        self.assertEqual(response.status_code, 401)

    def test_corrective_action_unauthorized(self):
        response = self.app.post('/corrective-action', json={'id': 1, 'description': 'test', 'due_date': '2023-01-01', 'assigned_to': 'test'})
        self.assertEqual(response.status_code, 401)

if __name__ == '__main__':
    unittest.main()
