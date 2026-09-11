import os
import sys
from urllib.parse import parse_qs, urlencode

# Ensure root directory is on Python path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from flask import jsonify
from studio_app import app

class VercelPathFixMiddleware:
    """
    Ensures seamless routing on Vercel Serverless Python runtime.
    Intercepts rewritten __route__ query parameter or X-Matched-Path headers
    and maps them to standard Flask WSGI PATH_INFO.
    """
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        query_string = environ.get('QUERY_STRING', '')
        
        # 1. Primary: Match from Vercel rewrite ?__route__=$1
        if '__route__' in query_string:
            params = parse_qs(query_string, keep_blank_values=True)
            if '__route__' in params:
                route = params.pop('__route__')[0]
                if not route.startswith('/'):
                    route = '/' + route
                environ['PATH_INFO'] = f'/api{route}' if not route.startswith('/api') else route
                environ['RAW_URI'] = environ['PATH_INFO']
                environ['REQUEST_URI'] = environ['PATH_INFO']
                flat = []
                for k, vs in params.items():
                    for v in vs:
                        flat.append((k, v))
                environ['QUERY_STRING'] = urlencode(flat)
        # 2. Secondary: Fallback to HTTP_X_MATCHED_PATH header
        elif 'HTTP_X_MATCHED_PATH' in environ and environ['HTTP_X_MATCHED_PATH'].startswith('/api'):
            environ['PATH_INFO'] = environ['HTTP_X_MATCHED_PATH']
        # 3. Tertiary: Fallback to HTTP_X_FORWARDED_URI header
        elif 'HTTP_X_FORWARDED_URI' in environ and environ['HTTP_X_FORWARDED_URI'].startswith('/api'):
            environ['PATH_INFO'] = environ['HTTP_X_FORWARDED_URI'].split('?')[0]

        return self.wsgi_app(environ, start_response)

# Attach middleware to Flask WSGI app
app.wsgi_app = VercelPathFixMiddleware(app.wsgi_app)

# Healthcheck fallback on root of API
@app.route("/api/index.py", methods=["GET", "POST"])
@app.route("/api", methods=["GET"])
@app.route("/api/", methods=["GET"])
def api_root():
    return jsonify({
        "service": "SENTINEL AI SOC Threat Forensics Engine",
        "status": "online",
        "version": "2.4.0",
        "engine": "17-Stage Deep Neural Forensics Pipeline",
        "endpoints": {
            "demo": "/api/forensics/demo/<safe|spam|phishing|suspicious>",
            "analyze": "/api/forensics/analyze",
            "stats": "/api/forensics/stats",
            "cases": "/api/forensics/cases"
        }
    })

app.debug = False
