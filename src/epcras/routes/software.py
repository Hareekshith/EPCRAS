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

@software_bp.route('/bulk-upgrade', methods=['POST'])
@login_required
@role_required(Role.ADMINISTRATOR, Role.IT_SUPPORT)
def bulk_upgrade():
    from epcras.services.software_service import fleet_wide_software_upgrade

    software_id_raw = request.form.get('software_id', '').strip()
    target_version = request.form.get('target_version', '').strip()
    current_version = request.form.get('current_version', '').strip()

    if not software_id_raw or not software_id_raw.isdigit():
        flash("Please select a valid software product.", "danger")
        return redirect(url_for('software.index'))

    if not target_version:
        flash("Target version cannot be empty.", "danger")
        return redirect(url_for('software.index'))

    software_id = int(software_id_raw)
    try:
        res = fleet_wide_software_upgrade(
            software_id=software_id,
            target_version=target_version,
            current_version=current_version if current_version else None
        )
        count = res['updated_count']
        assets_count = res['affected_assets_count']
        sw_name = res['software_name']
        if count > 0:
            flash(
                f"Fleet upgrade complete: Updated {count} installation(s) of '{sw_name}' to version {target_version} across {assets_count} asset(s). Compliance analysis automatically refreshed.",
                "success"
            )
        else:
            flash(f"No installations of '{sw_name}' required updating to version {target_version}.", "info")
    except Exception as e:
        flash(f"Fleet upgrade error: {str(e)}", "danger")

    return redirect(url_for('software.index'))

