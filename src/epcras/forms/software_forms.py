from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, SelectField, SubmitField
from wtforms.validators import DataRequired, Length, Optional

class SoftwareForm(FlaskForm):
    name = StringField(
        'Software Name',
        validators=[DataRequired(message='Software name is required.'), Length(max=128)],
        render_kw={"placeholder": "e.g., Firefox"}
    )
    vendor = StringField(
        'Vendor',
        validators=[DataRequired(message='Vendor is required.'), Length(max=128)],
        render_kw={"placeholder": "e.g., Mozilla"}
    )
    category = StringField(
        'Category',
        validators=[Optional(), Length(max=64)],
        render_kw={"placeholder": "e.g., Web Browser / Database / Runtime"}
    )
    submit = SubmitField('Save Software')

class InstalledSoftwareForm(FlaskForm):
    software_id = SelectField(
        'Software Application',
        coerce=int,
        validators=[DataRequired(message='Please select a software application.')]
    )
    version = StringField(
        'Installed Version',
        validators=[DataRequired(message='Installed version is required.'), Length(max=50)],
        render_kw={"placeholder": "e.g., 128.0.1"}
    )
    submit = SubmitField('Add Installed Software')

class CSVImportForm(FlaskForm):
    csv_file = FileField(
        'Inventory CSV File',
        validators=[
            FileRequired(message='Please select a CSV file to upload.'),
            FileAllowed(['csv'], message='Only CSV files are allowed.')
        ]
    )
    submit = SubmitField('Import Software Inventory')
