from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import bcrypt


app = Flask(__name__)
nonconformities = []
documents = []
app.secret_key = 'your_secret_key'

users = [
    {'username': 'reviewer1', 'password': bcrypt.hashpw('password1'.encode('utf-8'), bcrypt.gensalt())},
    {'username': 'reviewer2', 'password': bcrypt.hashpw('password2'.encode('utf-8'), bcrypt.gensalt())}
]

def is_authenticated():
    return 'username' in session

@app.route("/")
def Hello_qms():
  return render_template('home.html')
  


def index():
    if not is_authenticated():
        return redirect(url_for('login'))

    return render_template('index.html',
    nonconformities=nonconformities)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_authenticated():
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = next((user for user in users if user['username'] == username and user['password'] == password), None)
         if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error_message='Invalid credentials')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/add_nonconformity', methods=['POST'])
def add_nonconformity():
   if not is_authenticated():
        return redirect(url_for('login'))
    description = request.form.get('description')
    severity = request.form.get('severity')
    nonconformity = {'description': description, 'severity': severity}
    nonconformities.append(nonconformity)
    return redirect(url_for('index'))
    return render_template('index.html', nonconformities=nonconformities,
documents=documents)

@app.route('/approve_document', methods=['POST'])
def approve_document():
  if not is_authenticated():
        return redirect(url_for('login'))
    document_id = request.form.get('document_id')
    action = request.form.get('action')
    document = next((doc for doc in documents if doc['id'] == document_id), None)
    if document:
        if action == 'Approve':
            document['status'] = 'Approved'
        elif action == 'Reject':
            document['status'] = 'Rejected'
          return redirect(url_for('index'))
    return render_template('index.html', nonconformities=nonconformities, documents=documents)

@app.route('/audit', methods=['POST'])
def perform_audit():
   
    audit = Audit(audit_date=request.json['audit_date'],
                  auditor=request.json['auditor'],
                  findings=request.json['findings'])
    audit.add_finding('Additional finding')
    audit.print_report()

   
    return jsonify({'message': 'Audit performed successfully.'}), 200

@app.route('/risk-assessment', methods=['POST'])
def perform_risk_assessment():
    
    risk_assessment = RiskAssessment(process=request.json['process'],
                                     description=request.json['description'],
                                     likelihood=request.json['likelihood'],
                                     impact=request.json['impact'])
    risk_level = risk_assessment.calculate_risk_level()

    
    return jsonify({'risk_level': risk_level}), 200

@app.route('/analysis', methods=['POST'])
def perform_analysis():
    
    analysis = Analysis(data=request.json['data'])
    analysis_results = analysis.analyze_data()

   
    return jsonify(analysis_results), 200

if __name__ == '__main__':
  app.run(host='0.0.0.0', debug=True)

if __name__ == '__main__':
    app.run(debug=True)
{
  "audit_date": "2023-09-01",
  "auditor": "John Doe",
  "findings": ["Finding 1", "Finding 2"]
}
{
  "message": "Audit performed successfully."
}
