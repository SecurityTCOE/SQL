from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import urllib.parse
import html
import base64
import gzip
import io
from sklearn.feature_extraction.text import TfidfVectorizer
from waitress import serve

app = Flask(__name__)
CORS(app)  # Allow Cross-Origin Resource Sharing

# Load the trained models and TF-IDF vectorizers for SQL injection detection
model_sql = joblib.load("best_model_sql_1,48,000 payloads.pkl")

def decode_ascii_hex(encoded):
    try:
        return bytes.fromhex(encoded).decode('utf-8')
    except:
        return encoded

def decode_octal(encoded):
    try:
        return ''.join([chr(int(encoded[i:i+3], 8)) for i in range(0, len(encoded), 3)])
    except:
        return encoded

def decode_binary(encoded):
    try:
        return ''.join([chr(int(encoded[i:i+8], 2)) for i in range(0, len(encoded), 8)])
    except:
        return encoded

def decode_hex(encoded):
    try:
        return bytes.fromhex(encoded).decode('utf-8')
    except:
        return encoded

def decode_gzip(encoded):
    try:
        buf = io.BytesIO(encoded)
        with gzip.GzipFile(fileobj=buf) as f:
            return f.read().decode('utf-8')
    except:
        return encoded

def decode_payload(payload, max_iterations=50):
    for _ in range(max_iterations):
        decoded_payload = payload

        # Decode URL encoded payloads
        decoded_payload = urllib.parse.unquote(decoded_payload)
        
        # Decode HTML entities
        decoded_payload = html.unescape(decoded_payload)
        
        # Decode Base64 encoded payloads
        try:
            decoded_payload = base64.b64decode(decoded_payload).decode('utf-8')
        except:
            pass  # Ignore errors if decoding fails
        
        # Decode ASCII HEX
        decoded_payload = decode_ascii_hex(decoded_payload)
        
        # Decode Octal
        decoded_payload = decode_octal(decoded_payload)
        
        # Decode Binary
        decoded_payload = decode_binary(decoded_payload)
        
        # Decode Hex
        decoded_payload = decode_hex(decoded_payload)
        
        # Decode Gzip
        try:
            decoded_payload = decode_gzip(decoded_payload.encode())
        except:
            pass  # Ignore errors if decoding fails
        
        if decoded_payload == payload:
            break
        
        payload = decoded_payload

    return payload

@app.route('/sql_injection', methods=['POST'])
def detect_injections_api():
    username = request.json.get('username')
    password = request.json.get('password')
    
    # Decode the payloads
    decoded_username = decode_payload(username)
    decoded_password = decode_payload(password)
    
    # Predict SQL injection for username and password
    prediction_sql_username = model_sql.predict([decoded_username.lower()])
    prediction_sql_password = model_sql.predict([decoded_password.lower()])

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
