from flask import Flask, request, jsonify
from flask_cors import CORS
import secrets
import time
import threading

app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing

# Store for active keys - in production, use a database
active_keys = {}

# List of authorized users (move to secure database in production)
authorized_users = [
    'kai', 'andy_dowson', 'lucian', 'spacez', 'andy', 
    'ken_jinx', 'riyoshi_iro', 'ynot', 'spector_heedz', 
    'archon', 'krats', 'iro', 'khatem', 'arthur_maniac'
]

# Key expiration time in seconds (15 minutes)
KEY_EXPIRATION = 7 * 60

def clean_expired_keys():
    """Background thread to clean expired keys periodically"""
    while True:
        current_time = time.time()
        keys_to_remove = []
        
        for key, data in active_keys.items():
            if current_time > data['expires']:
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del active_keys[key]
            
        time.sleep(60)  # Check every minute

# Start the cleaning thread
cleaning_thread = threading.Thread(target=clean_expired_keys, daemon=True)
cleaning_thread.start()

@app.route('/verify-user', methods=['POST'])
def verify_user():
    """Endpoint to verify username and generate key"""
    data = request.json
    username = data.get('username', '').lower()
    
    if username not in authorized_users:
        return jsonify({
            'success': False,
            'message': 'Unauthorized user'
        }), 403
    
    # Generate a secure random key (32 hex characters)
    key = secrets.token_hex(16)
    
    # Store key with expiration
    current_time = time.time()
    active_keys[key] = {
        'username': username,
        'created': current_time,
        'expires': current_time + KEY_EXPIRATION
    }
    
    return jsonify({
        'success': True,
        'key': key
    })

@app.route('/validate-key', methods=['POST'])
def validate_key():
    """Endpoint to validate key and provide access"""
    data = request.json
    key = data.get('key', '')
    
    if key not in active_keys:
        return jsonify({
            'success': False,
            'message': 'Invalid or expired key'
        }), 403
    
    key_data = active_keys[key]
    current_time = time.time()
    
    # Check if key is expired
    if current_time > key_data['expires']:
        del active_keys[key]
        return jsonify({
            'success': False,
            'message': 'Key expired'
        }), 403
    
    # One-time use - remove key after validation
    username = key_data['username']
    del active_keys[key]
    
    return jsonify({
        'success': True,
        'username': username,
        'redirectUrl': '/main.html'
    })

if __name__ == '__main__':
   app.run(debug=False, host='0.0.0.0', port=5500)

