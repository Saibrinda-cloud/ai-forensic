from api import app
from flask import send_from_directory, send_file
import os

@app.route('/', methods=['GET'])
@app.route('/index.html', methods=['GET'])
def serve_index():
    try:
        return send_file(os.path.join(os.path.dirname(__file__), '..', 'frontend', 'index.html'))
    except:
        return "Frontend not found", 404

def handler(request):
    return app(request)
