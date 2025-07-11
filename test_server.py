from flask import Flask, jsonify
import os

app = Flask(__name__)

@app.route('/')
def hello():
    return jsonify({"message": "Hello from Railway!", "port": os.getenv('PORT', 'Not set')})

@app.route('/api/health')
def health():
    return jsonify({"status": "healthy", "port": os.getenv('PORT', 'Not set')})

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False) 