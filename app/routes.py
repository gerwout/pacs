#@todo: logging!
from app import app, oidc, db, models, forms
from flask import request, redirect, render_template, g, session, jsonify, abort
import re, hashlib, os, importlib
from sqlalchemy import desc
from app.utils.import_handler import import_handler
import platform
system = platform.system()
if system == 'Windows':
    import pythoncom
from pathlib import Path
from itsdangerous import (URLSafeTimedSerializer, TimedJSONWebSignatureSerializer, BadSignature, SignatureExpired)

def __verify_api_auth_token(token):
    s = TimedJSONWebSignatureSerializer(app.config['SECRET_API_KEY'])
    try:
        data = s.loads(token)
    except SignatureExpired:
        return False  # valid token, but expired
    except BadSignature:
        return False  # invalid token

    return data

def __generate_api_auth_token(json_dict, expiration=600):
    s = TimedJSONWebSignatureSerializer(app.config['SECRET_API_KEY'], expires_in=expiration)

    return s.dumps(json_dict).decode('utf-8')

def __csrf_token():
    csrf_token = hashlib.sha1(os.urandom(64)).hexdigest()
    s = URLSafeTimedSerializer(app.secret_key, salt=os.urandom(64))
    session['csrf_token'] = s.dumps(csrf_token)

    return session['csrf_token']

@app.route("/check-compliance", methods=['POST'])
def check_compliance():
    pacs_file = app.config['PACS_STATUS_FILE']
    if os.path.isfile(pacs_file):
        force_compliant = True
    else:
        force_compliant = False
    can_connect = True
    has_valid_signature = False
    # only handle the request when it contains application/json mimetype header
    # this is important to prevent CSRF kind of form posts
    if request.is_json:
        if not force_compliant:
            data = request.get_json()
            auth_token = data['auth_token']
            connection_data = __verify_api_auth_token(auth_token)
            # some form of signature error, assume False, because of auth failure
            if not connection_data:
                can_connect = False
            else:
                has_valid_signature = True
                engines = app.config['ENGINES'].split(",")
                for engine in engines:
                    anti_virus = importlib.import_module('app.antivirus.' + engine)
                    instance = getattr(anti_virus, engine)()
                    compliant = instance.check_compliance(connection_data)
                    if not compliant:
                        can_connect = False
                        break
        json_to_sign = {"compliant": can_connect, "has_valid_signature": has_valid_signature }
        auth_token = __generate_api_auth_token(json_to_sign)
        json_to_return = {"auth_token": auth_token}

        return jsonify(json_to_return)
    # not a request with the application/json header, could be a suspicious form post
    else:
         abort(404)

@app.route('/', methods=['GET', 'POST'], defaults={'order_by': 'id', 'asc_or_desc': 'asc'})
@app.route('/index/<order_by>/<asc_or_desc>', methods=['GET', 'POST'])
@oidc.require_login
def index(order_by, asc_or_desc):
    allowed_order_by_values = ['id', 'name', 'description', 'last_logon_name', 'ignore_av_check', 'source_id']
    allowed_asc_or_desc_values = ['asc', 'desc']
    order_by = order_by.lower()
    asc_or_desc = asc_or_desc.lower()
    if order_by not in allowed_order_by_values:
        order_by = 'id'
    if asc_or_desc not in allowed_asc_or_desc_values:
        asc_or_desc = 'asc'

    errors = []
    originals = []
    form = forms.ComputerForm()
    action = "add"
    if request.method == 'POST':
        if not 'csrf_token' in request.values or not 'csrf_token' in session:
            errors.append('No CSRF token available!')
        if session.get('csrf_token') != request.values.get('csrf_token'):
            errors.append('CSRF token not valid!')
        id = request.values.get('id', '').strip()

        if id != "" and not id.isdigit():
            errors.append('ID needs to numeric!')
        name = request.values.get('name', '').upper().strip()
        description = request.values.get('description', '').strip()
        ignore_av_check = request.values.get('ignore_av_check', False)
        ignore_av_check = True if ignore_av_check == "on" else False
        mac_addresses = list(filter(None, request.form.getlist('mac')))
        if name == "":
            errors.append('Name is a required field!')
        if description == "":
            errors.append('Description is a required field!')
        if len(mac_addresses) == 0:
            errors.append('Mac address is a required field!')

        for mac_address in mac_addresses:
            original = mac_address
            originals.append(original)
            mac_address = mac_address.replace(":", "").replace("-", "").replace(".", "").upper()
            if not re.match("^[A-Z0-9]{12}$", mac_address):
                errors.append('The mac address ' + original + " is not valid!")
            if id == "":
                count = models.MacAddress.query.filter_by(mac=mac_address).count()
            else:
                count = models.MacAddress.query.filter(models.MacAddress.comp_id != id).filter_by(mac=mac_address).count()

            if count > 0:
                errors.append('The mac address ' + original + " is already used by another computer!")

        if len(errors) == 0:
            result = models.Source.query.filter_by(name='manual').first()
            source_id = result.id
            # add new computer
            if id == "":
                comp = models.Computer(name=name, description=description, source_id=source_id, last_logon_name="", ignore_av_check=ignore_av_check)
                db.session.add(comp)
                db.session.flush()
                id = comp.id
            # edit existing computer
            else:
                comp = models.Computer.query.filter_by(id=id).first()
                comp.name = name
                comp.description = description
                comp.ignore_av_check = ignore_av_check
                models.MacAddress.query.filter_by(comp_id=id).delete()
            for mac_address in mac_addresses:
                mac_address = mac_address.replace(":", "").replace("-", "").replace(".", "").upper()
                mac = models.MacAddress(comp_id=id, mac=mac_address)
                db.session.add(mac)
            db.session.commit()
            # lets reset the form values
            id = ""
            name = ""
            description = ""
            ignore_av_check = False
            originals = []
        elif len(errors) > 0 and id.isdigit():
            action = "edit"
    else:
        id = ""
        name = ""
        description = ""
        ignore_av_check = False

    form.name.data = name
    form.description.data = description
    if len(originals) == 0:
        originals.append("")
    if asc_or_desc == "asc":
        computers = models.Computer.query.order_by(order_by).all()
    else:
        computers = models.Computer.query.order_by(desc(order_by)).all()

    csrf_token = __csrf_token()

    show_sccm_button = app.config.get('SCCM_SHOW_BUTTON', False)
    pacs_file = app.config['PACS_STATUS_FILE']
    if os.path.isfile(pacs_file):
        pacs_enabled = False
    else:
        pacs_enabled = True

    return render_template('index.html', form=form, errors=errors, mac_addresses=originals, computers=computers,
                           csrf_token=csrf_token, action=action, id=id, ignore_av_check=ignore_av_check,
                           logon=g.sso_identity, order_by=order_by, asc_or_desc=asc_or_desc,
                           show_sccm_button=show_sccm_button, pacs_enabled=pacs_enabled)

@app.route('/delete/<int:computer_id>', methods=['POST'])
@oidc.require_login
def delete_computer(computer_id):
    errors = []
    if not 'csrf_token' in request.values or not 'csrf_token' in session:
        errors.append('No CSRF token available!')
    if session.get('csrf_token') != request.values.get('csrf_token'):
        errors.append('CSRF token not valid!')
    if len(errors) > 0:
        return jsonify({"success": False, "errors": errors })
    else:
        models.MacAddress.query.filter_by(comp_id=computer_id).delete()
        models.Computer.query.filter_by(id=computer_id).delete()
        db.session.commit()

        return jsonify({"success": True })

@app.before_request
def check_if_authenticated():
    user_logged_in = oidc.user_loggedin

    if request.path != "/check-compliance" and not user_logged_in:
        return oidc.authenticate_or_redirect()
    elif user_logged_in:
        user_info = oidc.user_getinfo(['name', 'email'])
        g.sso_identity = user_info['name'] + " (" + user_info['email'] + ")"

@app.route('/disable_or_enable_pacs', methods=['POST'])
@oidc.require_login
def disable_or_enable_pacs():
    errors = []
    if not 'csrf_token' in request.values or not 'csrf_token' in session:
        errors.append('No CSRF token available!')
    if session.get('csrf_token') != request.values.get('csrf_token'):
        errors.append('CSRF token not valid!')
    csrf_token = __csrf_token()
    if len(errors) == 0:
        pacs_file = app.config['PACS_STATUS_FILE']
        if os.path.isfile(pacs_file):
            os.remove(pacs_file)
            message = "Enabled compliance check for PACS!\n"
        else:
            Path(pacs_file).touch()
            message = "Disabled compliance check for PACS!\n"
    else:
        message = "Not going to do this!\n"
        for error in errors:
            message = message + error + "\n"

    return jsonify({"message": message, "csrf_token": csrf_token})

@app.route("/logout")
def logout():
    oidc.logout()
    return redirect(app.config['LOGOUT_REDIRECT'])

@app.route('/sccm_import', methods=['POST'])
@oidc.require_login
def sccm_import():
    if app.config['SCCM_SHOW_BUTTON']:
        errors = []
        if not 'csrf_token' in request.values or not 'csrf_token' in session:
            errors.append('No CSRF token available!')
        if session.get('csrf_token') != request.values.get('csrf_token'):
            errors.append('CSRF token not valid!')
        csrf_token = __csrf_token()
        if len(errors) == 0:
            # avoid threading issues on WIndows
            if system == 'Windows':
                pythoncom.CoInitialize()
            sccm_import = import_handler()
            message = sccm_import.import_from_sccm_and_ad()
        else:
            message = "Import failed!\n"
            for error in errors:
                message = message + error + "\n"

        return jsonify({"message": message, "csrf_token": csrf_token})
