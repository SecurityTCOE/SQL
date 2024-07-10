from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from waitress import serve

app = Flask(__name__)
CORS(app)  # Allow Cross-Origin Resource Sharing

# Load the trained models and TF-IDF vectorizers for SQL injection, XSS, and HTML injection detection
model_sql = joblib.load("best_model_sql_1,48,000 payloads.pkl")

@app.route('/sql injection', methods=['POST'])
def detect_injections_api():
    username = request.json.get('username')
    password = request.json.get('password')
    
    # Predict SQL injection for username and password
    prediction_sql_username = model_sql.predict([username.lower()])
    prediction_sql_password = model_sql.predict([password.lower()])

    response = {
        "username_is_sql_injection": bool(prediction_sql_username),
        "password_is_sql_injection": bool(prediction_sql_password),

    }

    if response["username_is_sql_injection"] or response["password_is_sql_injection"]:
        response["message"] = "Malicious Input detected"
    else:
        response["message"] = "No injection detected"

    return jsonify(response)

if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=4090)