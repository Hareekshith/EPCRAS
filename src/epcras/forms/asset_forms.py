from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, IPAddress, Optional, Length
from epcras.models.asset import Criticality

ASSET_TYPES = [
    ('Workstation', 'Workstation'),
    ('Server', 'Server'),
    ('Laptop', 'Laptop'),
    ('Virtual Machine', 'Virtual Machine'),
    ('Network Device', 'Network Device'),
]

class AssetForm(FlaskForm):
    hostname = StringField(
        'Hostname',
        validators=[DataRequired(message='Hostname is required.'), Length(max=128)],
        render_kw={"placeholder": "e.g., PC-FINANCE-01"}
    )
    ip_address = StringField(
        'IP Address',
        validators=[DataRequired(message='IP Address is required.'), IPAddress(message='Invalid IP Address format.')],
        render_kw={"placeholder": "e.g., 192.168.1.50"}
    )
    operating_system = StringField(
        'Operating System',
        validators=[DataRequired(message='Operating System is required.'), Length(max=100)],
        render_kw={"placeholder": "e.g., Ubuntu Linux / Windows 11"}
    )
    os_version = StringField(
        'OS Version',
        validators=[Optional(), Length(max=50)],
        render_kw={"placeholder": "e.g., 22.04 LTS / 23H2"}
    )
    department_id = SelectField(
        'Department',
        coerce=int,
        validators=[Optional()]
    )
    owner = StringField(
        'Owner / Custodian',
        validators=[Optional(), Length(max=100)],
        render_kw={"placeholder": "e.g., John Doe / SysAdmin"}
    )
    asset_type = SelectField(
        'Asset Type',
        choices=ASSET_TYPES,
        default='Workstation'
    )
    criticality = SelectField(
        'Criticality Level',
        choices=Criticality.choices(),
        default=Criticality.MEDIUM
    )
    submit = SubmitField('Save Asset')

class DepartmentForm(FlaskForm):
    name = StringField(
        'Department Name',
        validators=[DataRequired(message='Department name is required.'), Length(max=64)],
        render_kw={"placeholder": "e.g., IT Security / Finance"}
    )
    description = StringField(
        'Description',
        validators=[Optional(), Length(max=256)],
        render_kw={"placeholder": "Department description"}
    )
    submit = SubmitField('Save Department')
