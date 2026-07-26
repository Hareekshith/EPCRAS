import os
import sys
import pytest

# Add src directory to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from epcras import create_app, db
from epcras.models.user import User, Role

@pytest.fixture
def app():
    app = create_app('testing')
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def runner(app):
    return app.test_cli_runner()

@pytest.fixture
def admin_user(app):
    user = User(
        username='admin_test',
        email='admin@test.com',
        role=Role.ADMINISTRATOR,
        is_active=True
    )
    user.set_password('AdminSecret123!')
    db.session.add(user)
    db.session.commit()
    return user

@pytest.fixture
def analyst_user(app):
    user = User(
        username='analyst_test',
        email='analyst@test.com',
        role=Role.SECURITY_ANALYST,
        is_active=True
    )
    user.set_password('AnalystSecret123!')
    db.session.add(user)
    db.session.commit()
    return user

@pytest.fixture
def support_user(app):
    user = User(
        username='support_test',
        email='support@test.com',
        role=Role.IT_SUPPORT,
        is_active=True
    )
    user.set_password('SupportSecret123!')
    db.session.add(user)
    db.session.commit()
    return user
