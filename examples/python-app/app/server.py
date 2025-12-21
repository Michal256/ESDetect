import os
import sys
import logging
from flask import Flask, jsonify

# Import libraries to test detection
import requests
import numpy as np
import yaml
from cryptography.fernet import Fernet

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# Generate a key for cryptography test
key = Fernet.generate_key()
cipher_suite = Fernet(key)

@app.route('/')
def hello():
    return "Hello from BPF Test Server!"

@app.route('/test-libs')
def test_libs():
    results = {}
    
    # Test requests
    try:
        # Just checking version to ensure loaded
        results['requests'] = requests.__version__
    except Exception as e:
        results['requests'] = str(e)

    # Test numpy
    try:
        arr = np.array([1, 2, 3])
        results['numpy'] = str(arr.tolist())
    except Exception as e:
        results['numpy'] = str(e)

    # Test yaml
    try:
        data = {'name': 'bpf-test', 'status': 'active'}
        results['yaml'] = yaml.dump(data)
    except Exception as e:
        results['yaml'] = str(e)

    # Test cryptography
    try:
        text = b"Secret Message"
        cipher_text = cipher_suite.encrypt(text)
        plain_text = cipher_suite.decrypt(cipher_text)
        results['cryptography'] = plain_text.decode()
    except Exception as e:
        results['cryptography'] = str(e)

    return jsonify(results)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    logging.info(f"Starting server on port {port}")
    
    # Access libraries on startup to ensure BPF sees them immediately
    logging.info(f"Requests version: {requests.__version__}")
    logging.info(f"Numpy version: {np.__version__}")
    logging.info(f"YAML version: {yaml.__version__}")
    
    app.run(host='0.0.0.0', port=port)
