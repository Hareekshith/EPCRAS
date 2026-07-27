from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, Length, Optional
from epcras.models.user import Role

class UserCreateForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[DataRequired(message='Username is required.'), Length(min=3, max=64)],
        render_kw={"placeholder": "e.g., jsmith"}
    )
    email = StringField(
        'Email Address',
        validators=[DataRequired(message='Email is required.'), Email(message='Invalid email format.'), Length(max=120)],
        render_kw={"placeholder": "e.g., jsmith@epcras.local"}
    )
    password = PasswordField(
        'Password',
        validators=[DataRequired(message='Password is required.'), Length(min=8, message='Password must be at least 8 characters.')],
        render_kw={"placeholder": "••••••••"}
    )
    role = SelectField(
        'Role Assignment',
        choices=Role.choices(),
        validators=[DataRequired(message='Role is required.')]
    )
    is_active = BooleanField('Account Active', default=True)
    submit = SubmitField('Create Account')

class UserEditForm(FlaskForm):
    username = StringField('Username', render_kw={"readonly": True})
    email = StringField(
        'Email Address',
        validators=[DataRequired(message='Email is required.'), Email(message='Invalid email format.'), Length(max=120)]
    )
    password = PasswordField(
        'New Password (Optional)',
        validators=[Optional(), Length(min=8, message='Password must be at least 8 characters.')],
        render_kw={"placeholder": "Leave blank to keep current password"}
    )
    role = SelectField(
        'Role Assignment',
        choices=Role.choices(),
        validators=[DataRequired(message='Role is required.')]
    )
    is_active = BooleanField('Account Active')
    submit = SubmitField('Update Account')
