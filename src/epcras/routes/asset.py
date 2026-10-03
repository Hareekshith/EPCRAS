from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required
from epcras.models.user import Role
from epcras.models.asset import Criticality, Department
from epcras.services.auth_service import role_required
from epcras.services.asset_service import (
    get_all_assets, get_asset_by_id, create_asset, update_asset, delete_asset,
    get_all_departments, create_department
)
from epcras.services.software_service import (
    get_all_software, add_installed_software, remove_installed_software
)
from epcras.forms.asset_forms import AssetForm, DepartmentForm
from epcras.forms.software_forms import InstalledSoftwareForm

asset_bp = Blueprint('asset', __name__, url_prefix='/assets')

@asset_bp.route('/', methods=['GET'])
@login_required
@role_required(Role.ADMINISTRATOR, Role.IT_SUPPORT, Role.SECURITY_ANALYST, Role.AUDITOR)
def index():
    search_q = request.args.get('search', '').strip()
    criticality = request.args.get('criticality', '').strip()
    dept_id_raw = request.args.get('department_id', '').strip()
    asset_type = request.args.get('asset_type', '').strip()

    dept_id = int(dept_id_raw) if dept_id_raw.isdigit() else None

    assets = get_all_assets(
        search_query=search_q if search_q else None,
        criticality=criticality if criticality in Criticality.all_levels() else None,
        department_id=dept_id,
        asset_type=asset_type if asset_type else None
    )

    departments = get_all_departments()

    return render_template(
        'assets/index.html',
        assets=assets,
        departments=departments,
        criticalities=Criticality.all_levels(),
        search_q=search_q,
        criticality_filter=criticality,
        dept_filter=dept_id,
        asset_type_filter=asset_type
    )

@asset_bp.route('/<int:asset_id>', methods=['GET'])
@login_required
@role_required(Role.ADMINISTRATOR, Role.IT_SUPPORT, Role.SECURITY_ANALYST, Role.AUDITOR)
def detail(asset_id):
    asset = get_asset_by_id(asset_id)
    if not asset:
        flash('Asset not found.', 'danger')
        return redirect(url_for('asset.index'))

    installed_form = InstalledSoftwareForm()
    software_list = get_all_software()
    installed_form.software_id.choices = [(sw.id, f"{sw.name} ({sw.vendor})") for sw in software_list]

    return render_template(
        'assets/detail.html',
        asset=asset,
        installed_form=installed_form
    )

@asset_bp.route('/new', methods=['GET', 'POST'])
@login_required
@role_required(Role.ADMINISTRATOR, Role.IT_SUPPORT)
def create():
    form = AssetForm()
    departments = get_all_departments()
    form.department_id.choices = [(0, '-- None --')] + [(d.id, d.name) for d in departments]

    if form.validate_on_submit():
        data = {
            'hostname': form.hostname.data,
            'ip_address': form.ip_address.data,
            'operating_system': form.operating_system.data,
            'os_version': form.os_version.data,
            'department_id': form.department_id.data if form.department_id.data != 0 else None,
            'owner': form.owner.data,
            'asset_type': form.asset_type.data,
            'criticality': form.criticality.data
        }
        try:
            asset = create_asset(data)
            flash(f"Asset '{asset.hostname}' created successfully.", 'success')
            return redirect(url_for('asset.detail', asset_id=asset.id))
        except ValueError as e:
            flash(str(e), 'danger')

    return render_template('assets/form.html', form=form, title='Create IT Asset')

@asset_bp.route('/<int:asset_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required(Role.ADMINISTRATOR, Role.IT_SUPPORT)
def edit(asset_id):
    asset = get_asset_by_id(asset_id)
    if not asset:
        flash('Asset not found.', 'danger')
        return redirect(url_for('asset.index'))

    form = AssetForm(obj=asset)
    departments = get_all_departments()
    form.department_id.choices = [(0, '-- None --')] + [(d.id, d.name) for d in departments]

    if request.method == 'GET':
        form.department_id.data = asset.department_id if asset.department_id else 0

    if form.validate_on_submit():
        data = {
            'hostname': form.hostname.data,
            'ip_address': form.ip_address.data,
            'operating_system': form.operating_system.data,
            'os_version': form.os_version.data,
            'department_id': form.department_id.data if form.department_id.data != 0 else None,
            'owner': form.owner.data,
            'asset_type': form.asset_type.data,
            'criticality': form.criticality.data
        }
        try:
            updated = update_asset(asset_id, data)
            flash(f"Asset '{updated.hostname}' updated successfully.", 'success')
            return redirect(url_for('asset.detail', asset_id=updated.id))
        except ValueError as e:
            flash(str(e), 'danger')

    return render_template('assets/form.html', form=form, title=f'Edit Asset: {asset.hostname}', asset=asset)

@asset_bp.route('/<int:asset_id>/delete', methods=['POST'])
@login_required
@role_required(Role.ADMINISTRATOR, Role.IT_SUPPORT)
def delete(asset_id):
    asset = get_asset_by_id(asset_id)
    if asset:
        hostname = asset.hostname
        delete_asset(asset_id)
        flash(f"Asset '{hostname}' deleted.", 'info')
    return redirect(url_for('asset.index'))

@asset_bp.route('/<int:asset_id>/software/add', methods=['POST'])
@login_required
@role_required(Role.ADMINISTRATOR, Role.IT_SUPPORT)
def add_software(asset_id):
    asset = get_asset_by_id(asset_id)
    if not asset:
        flash('Asset not found.', 'danger')
        return redirect(url_for('asset.index'))

    form = InstalledSoftwareForm()
    software_list = get_all_software()
    form.software_id.choices = [(sw.id, f"{sw.name} ({sw.vendor})") for sw in software_list]

    if form.validate_on_submit():
        try:
            add_installed_software(
                asset_id=asset.id,
                software_id=form.software_id.data,
                version=form.version.data
            )
            flash('Installed software linked successfully.', 'success')
        except ValueError as e:
            flash(str(e), 'danger')
    else:
        for field, errs in form.errors.items():
            for e in errs:
                flash(f"{field}: {e}", 'danger')

    return redirect(url_for('asset.detail', asset_id=asset_id))

@asset_bp.route('/<int:asset_id>/software/<int:installed_sw_id>/delete', methods=['POST'])
@login_required
@role_required(Role.ADMINISTRATOR, Role.IT_SUPPORT)
def delete_software(asset_id, installed_sw_id):
    if remove_installed_software(installed_sw_id):
        flash('Software association removed from asset.', 'info')
    else:
        flash('Software association not found.', 'danger')
    return redirect(url_for('asset.detail', asset_id=asset_id))

@asset_bp.route('/<int:asset_id>/software/<int:installed_sw_id>/update', methods=['POST'])
@login_required
@role_required(Role.ADMINISTRATOR, Role.IT_SUPPORT)
def update_software(asset_id, installed_sw_id):
    from epcras.services.software_service import update_installed_software_version

    new_version = request.form.get('version', '').strip()
    if not new_version:
        flash("Software version cannot be empty.", 'danger')
        return redirect(url_for('asset.detail', asset_id=asset_id))

    try:
        res = update_installed_software_version(installed_sw_id, new_version, trigger_compliance=True)
        flash(f"Updated '{res['software_name']}' to version {new_version}. Compliance analysis refreshed.", 'success')
    except Exception as e:
        flash(f"Update error: {str(e)}", 'danger')

    return redirect(url_for('asset.detail', asset_id=asset_id))

@asset_bp.route('/departments', methods=['GET', 'POST'])
@login_required
@role_required(Role.ADMINISTRATOR, Role.IT_SUPPORT)
def departments():
    form = DepartmentForm()
    if form.validate_on_submit():
        dept = create_department(form.name.data, form.description.data)
        flash(f"Department '{dept.name}' created.", 'success')
        return redirect(url_for('asset.departments'))

    depts = get_all_departments()
    return render_template('assets/departments.html', form=form, departments=depts)
