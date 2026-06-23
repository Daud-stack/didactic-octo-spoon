import unittest
from unittest.mock import patch, MagicMock
from app import app

class TestAuditEndpoint(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    @patch('app.Audit', create=True)
    def test_perform_audit_success(self, MockAudit):
        mock_audit_instance = MockAudit.return_value

        response = self.client.post('/audit', json={
            "audit_date": "2023-09-01",
            "auditor": "John Doe",
            "findings": ["Finding 1", "Finding 2"]
        })

        MockAudit.assert_called_once_with(
            audit_date="2023-09-01",
            auditor="John Doe",
            findings=["Finding 1", "Finding 2"]
        )

        mock_audit_instance.add_finding.assert_called_once_with('Additional finding')
        mock_audit_instance.print_report.assert_called_once()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {'message': 'Audit performed successfully.'})

    @patch('app.Audit', create=True)
    def test_perform_audit_missing_fields(self, MockAudit):
        response = self.client.post('/audit', json={
            "audit_date": "2023-09-01",
            # missing auditor and findings
        })
        # App will raise KeyError because request.json['auditor'] will fail.
        self.assertEqual(response.status_code, 500)

if __name__ == '__main__':
    unittest.main()
