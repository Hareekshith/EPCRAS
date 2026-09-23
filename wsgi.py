"""
WSGI entrypoint for EPCRAS production deployment with Gunicorn / uWSGI.
"""
import os
from epcras import create_app

# Select configuration environment (defaults to production for WSGI servers)
config_name = os.environ.get('FLASK_CONFIG', 'production')
app = create_app(config_name)

if __name__ == "__main__":
    app.run()
