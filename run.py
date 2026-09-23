import os
from epcras import create_app, db

env = os.environ.get('FLASK_CONFIG', 'development')
app = create_app(env)

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    debug_mode = app.config.get('DEBUG', False)
    host = os.environ.get('FLASK_HOST', '127.0.0.1')
    port = int(os.environ.get('FLASK_PORT', 5000))
    app.run(host=host, port=port, debug=debug_mode)
