import os
from epcras import create_app, db

env = os.environ.get('FLASK_CONFIG', 'development')
app = create_app(env)

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
