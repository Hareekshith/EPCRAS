from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired

class LoginForm(FlaskForm):
    username_or_email = StringField(
        'Username or Email',
        validators=[DataRequired(message='Username or Email is required.')],
        render_kw={"placeholder": "Enter username or email", "autocomplete": "username"}
    )
    password = PasswordField(
        'Password',
        validators=[DataRequired(message='Password is required.')],
        render_kw={"placeholder": "Enter password", "autocomplete": "current-password"}
    )
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')
