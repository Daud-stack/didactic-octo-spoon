import time
from app import app, documents
import app as app_module

# Add 100,000 documents
for i in range(100000):
    if isinstance(documents, list):
        documents.append({'id': str(i), 'status': 'Pending'})
    else:
        documents[str(i)] = {'id': str(i), 'status': 'Pending'}

with app.test_client() as client:
    with client.session_transaction() as sess:
        sess['username'] = 'reviewer1'

    start_time = time.time()
    for _ in range(100):
        # target the last document to show worst-case performance for list
        client.post('/approve_document', data={'document_id': '99999', 'action': 'Approve'})

    end_time = time.time()

print(f"Time taken: {end_time - start_time:.4f} seconds")
