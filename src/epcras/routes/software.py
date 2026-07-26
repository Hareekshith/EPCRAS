from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required
from epcras.models.user import Role
from epcras.services.auth_service import role_required
from epcras.services.software_service import (
    get_all_software, get_or_create_software, import_software_csv
)
from epcras.forms.software_forms import SoftwareForm, CSVImportForm

software_bp = Blueprint('software', __name__, url_prefix='/software')

@software_bp.route('/', methods=['GET'])
@login_required
@role_required(Role.ADMINISTRATOR, Role.IT_SUPPORT, Role.SECURITY_ANALYST, Role.AUDITOR)
def index():
    software_list = get_all_software()
    return render_template('software/index.html', software_list=software_list)

@software_bp.route('/new', methods=['GET', 'POST'])
@login_required
@role_required(Role.ADMINISTRATOR, Role.IT_SUPPORT)
def create():
    form = SoftwareForm()
    if form.validate_on_submit():
        sw = get_or_create_software(
            name=form.name.data,
            vendor=form.vendor.data,
            category=form.category.data
        )
        flash(f"Software '{sw.name}' ({sw.vendor}) added to catalogue.", 'success')
        return redirect(url_for('software.index'))

    return render_template('software/form.html', form=form)

@software_bp.route('/import', methods=['GET', 'POST'])
@login_required
@role_required(Role.ADMINISTRATOR, Role.IT_SUPPORT)
def import_csv():
    form = CSVImportForm()
    errors = []
    success_count = 0

    if form.validate_on_submit():
        csv_file = form.csv_file.data
        result = import_software_csv(csv_file.stream)
        success_count = result.get('success_count', 0)
        errors = result.get('errors', [])

        if success_count > 0:
            flash(f"Successfully imported {success_count} software inventory records.", 'success')
        if not errors and success_count > 0:
            return redirect(url_for('asset.index'))

    return render_template('software/import.html', form=form, errors=errors, success_count=success_count)
