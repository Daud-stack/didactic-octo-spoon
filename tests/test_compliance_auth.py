import unittest
from unittest.mock import patch, MagicMock
from app import app, nonconformities, documents

class TestComplianceAuth(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.secret_key = 'test_secret'
        self.client = app.test_client()
        # Reset memory state
        nonconformities.clear()
        documents.clear()

    @patch('app.ComplianceItem', create=True)
    def test_update_compliance_unauthenticated(self, mock_compliance_item):
        payload = {
            'id': '123',
            'name': 'Test Item',
            'description': 'Test Desc',
            'status': 'Open',
            'new_status': 'Closed'
        }
        response = self.client.post('/compliance', json=payload)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json, {'message': 'Unauthorized'})
        mock_compliance_item.assert_not_called()

    @patch('app.ComplianceItem', create=True)
    def test_update_compliance_authenticated(self, mock_compliance_item):
        mock_instance = MagicMock()
        mock_compliance_item.return_value = mock_instance

        payload = {
            'id': '123',
            'name': 'Test Item',
            'description': 'Test Desc',
            'status': 'Open',
            'new_status': 'Closed'
        }

        with self.client.session_transaction() as sess:
            sess['username'] = 'testuser'

        response = self.client.post('/compliance', json=payload)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {'message': 'Compliance item updated successfully.'})
        mock_compliance_item.assert_called_once_with('123', 'Test Item', 'Test Desc', 'Open')
        mock_instance.update_status.assert_called_once_with('Closed')

if __name__ == '__main__':
    unittest.main()
