#@todo query 2fa status in logs?
from app import app, oidc, db, models, forms, csrf
from flask import request, redirect, render_template, g, jsonify, abort
import re, os, importlib
from sqlalchemy import desc
from app.utils.import_handler import import_handler
from app.utils.mongo_handler import mongo_handler
import platform, datetime
system = platform.system()
if system == 'Windows':
    import pythoncom
from pathlib import Path
from itsdangerous import (TimedJSONWebSignatureSerializer, BadSignature, SignatureExpired)

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

@app.route("/check-compliance", methods=['POST'])
@csrf.exempt
def check_compliance():
    mongo = mongo_handler()
    mongo.add_to_audit_trail("unknown", "Start check compliance check", "User is unknown, because we did not determine that yet")
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
        data = request.get_json()
        auth_token = data['auth_token']
        # so, PACS is system wide enabled, we need to verify the compliance status
        if not force_compliant:
            connection_data = __verify_api_auth_token(auth_token)
            # some form of signature error, assume False, because of auth failure
            if not connection_data:
                mongo.add_to_audit_trail("unknown", "JWT signature failed!",
                                         "Suspicious request auth_token: " + auth_token)
                mongo.add_to_audit_trail("unknown", "JWT signature failed!", "Not going to allow this connection")

                can_connect = False
            else:
                connection_data['timestamp'] = datetime.datetime.now().timestamp()
                log_id = mongo.add_to_logs(connection_data)
                has_valid_signature = True
                identifier = connection_data['mac_addr'].upper()

                # we need to do a device id lookup
                if re.match("^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$", identifier) and models.Computer.query.filter_by(device_id=identifier).count() == 0:
                    mongo.add_to_audit_trail(connection_data['user_name'], "Device ID " + str(identifier) + " not found in PACS!",
                                             "Not going to allow this connection")
                    can_connect = False
                # ok, no device id, when then it has to be a mac address
                elif models.MacAddress.query.filter_by(mac=identifier.replace(":", "").replace("-", "").replace(".", "")).count() == 0:
                    mongo.add_to_audit_trail(connection_data['user_name'],
                                             "Mac address " + str(identifier) + " not found in PACS!",
                                             "Not going to allow this connection")
                    can_connect = False
                else:
                    engines = app.config['ENGINES'].split(",")
                    mongo.add_to_audit_trail(connection_data['user_name'], "JWT signature passed! log_id: " + str(log_id),
                                             "Going to check compliance status")

                    for engine in engines:
                        mongo.add_to_audit_trail(connection_data['user_name'],
                                                 "Checking app.antivirus." + engine,
                                                 "")

                        anti_virus = importlib.import_module('app.antivirus.' + engine)
                        instance = getattr(anti_virus, engine)()
                        compliant = instance.check_compliance(connection_data)
                        if not compliant:
                            mongo.add_to_audit_trail(connection_data['user_name'],
                                                     "Checking app.antivirus." + engine,
                                                     "Not compliant or not in healthy state!, refuse connection")
                            can_connect = False
                            break
                        else:
                            mongo.add_to_audit_trail(connection_data['user_name'],
                                                     "Checking app.antivirus." + engine,
                                                     "Compliant and healthy")
        else:
            mongo.add_to_audit_trail("unknown", "Compliance check disabled system wide", "Going to allow this connection")
            # even though we are not going to check the data that has been sent (i.e. compliance check is disabled system wide)
            # we do want to log who did the request
            connection_data = __verify_api_auth_token(auth_token)
            # some form of signature error, assume False, because of auth failure
            if not connection_data:
                has_valid_signature = False
                mongo.add_to_audit_trail("unknown", "Ignoring (i.e. system wide PACS disabled) JWT signature failed!",
                                         "Suspicious request auth_token: " + auth_token)
            else:
                connection_data['timestamp'] = datetime.datetime.now().timestamp()
                log_id = mongo.add_to_logs(connection_data)
                has_valid_signature = True
                mongo.add_to_audit_trail(connection_data['user_name'], "JWT signature passed! log_id: " + str(log_id),
                                         "Not going to check compliance status (PACS system wide disabled)")

        json_to_sign = {"compliant": can_connect, "has_valid_signature": has_valid_signature }
        auth_token = __generate_api_auth_token(json_to_sign)
        json_to_return = {"auth_token": auth_token}
        try:
            if not connection_data:
                user_name = "unknown"
            else:
                user_name = connection_data['user_name']

            mongo.add_to_audit_trail(user_name, "Connection allowed: " + str(can_connect), "logid: " + str(log_id))
        except NameError:
            pass

        return jsonify(json_to_return)
    # not a request with the application/json header, could be a suspicious form post
    else:
        mongo.add_to_audit_trail("unknown", "Compliance check was not posted as mimetype JSON!",
                                 "This could be someone trying to hack the service")
        abort(404)

@app.route('/logs', methods=['GET', 'POST'])
@oidc.require_login
def logs():
    mongo = mongo_handler()
    form = forms.LogSearchForm()
    all_users = mongo.get_unique_users()
    all_macs = mongo.get_unique_macs()
    all_ips = mongo.get_unique_ips()

    # succesfull form post, get values
    if form.validate_on_submit():
        start = datetime.datetime.strptime(request.form['start_date_time'], "%Y-%m-%dT%H:%M:%S")
        end = datetime.datetime.strptime(request.form['end_date_time'], "%Y-%m-%dT%H:%M:%S")
        user = request.form['user']
        mac = request.form['mac']
        ip = request.form['ip']

        all_logs = mongo.get_all_logs(start=start, end=end, user=user, mac=mac, ip=ip)
        audit_trail = mongo.get_audit_trail(start=start, end=end, user=user)
    else:
        all_logs = mongo.get_all_logs()
        audit_trail = mongo.get_audit_trail()
    logs = []

    for idx, audit in enumerate(audit_trail):
        temp_log = {}
        dt = datetime.datetime.utcfromtimestamp(audit['timestamp'])
        temp_log['timestamp'] = audit['timestamp']
        temp_log['datetime'] = dt.strftime("%d-%m-%Y %H:%M:%S")
        temp_log['user'] = audit['user']
        temp_log['action'] = audit['action']
        temp_log['result'] = audit['result']
        temp_log['type'] = "audit"
        logs.append(temp_log)

    for idx, log in enumerate(all_logs):
        temp_log = {}
        dt = datetime.datetime.utcfromtimestamp(log['timestamp'])
        temp_log['datetime'] = dt.strftime("%d-%m-%Y %H:%M:%S")
        temp_log['timestamp'] = log['timestamp']
        temp_log['user'] = log['user_name']
        if log['user_has_pin'] == "True":
            temp_log['user'] = temp_log['user'] + " (user has pin!)"
        temp_log['action'] = "Checking: " + str(log['mac_addr']) + " from " + str(log['remote_ip']) + " (" + str(log['platform']) + ")"
        temp_log['action'] = temp_log['action'] + " " + str(log['org_name']) + " - " + str(log['server_name']) + " (" + str(log['host_name']) + ") -> " + str(log['server_protocol']) + ":" + str(log['server_port'])
        temp_log['action'] = temp_log['action'] + " (log id:" + str(log['_id']) + ")"
        temp_log['type'] = "log"
        logs.append(temp_log)

    sorted_logs = sorted(logs, key = lambda i: i['timestamp'], reverse=True)

    return render_template('logs.html', show_sccm_button=False, logon=g.sso_identity, show_pacs_button=False,
                           show_home_button=True, show_logs_button=False, logs=sorted_logs, form=form, users=all_users,
                           macs=all_macs, ips=all_ips, version=app.config['VERSION'])

@app.route('/', methods=['GET', 'POST'], defaults={'order_by': 'id', 'asc_or_desc': 'asc'})
@app.route('/index/<order_by>/<asc_or_desc>', methods=['GET', 'POST'])
@oidc.require_login
def index(order_by, asc_or_desc):
    mongo = mongo_handler()
    allowed_order_by_values = ['id', 'name', 'description', 'last_logon_name', 'device_id', 'ignore_av_check', 'source_id']
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
        id = request.values.get('id', '').strip()

        if id != "" and not id.isdigit():
            errors.append('ID needs to numeric!')
        name = request.values.get('name', '').upper().strip()
        description = request.values.get('description', '').strip()
        ignore_av_check = request.values.get('ignore_av_check', False)
        ignore_av_check = True if ignore_av_check == "on" else False
        mac_addresses = list(filter(None, request.form.getlist('mac')))
        device_id = request.values.get('device_id', '').strip().upper()

        if name == "":
            errors.append('Name is a required field!')
        if description == "":
            errors.append('Description is a required field!')
        if len(mac_addresses) == 0 and device_id == "":
            errors.append('You need to supply one or more mac addresses or a device id!')
        if len(mac_addresses) > 0 and device_id != "":
            errors.append("You can't supply a mac address and a device id!")
        # example: 8F2D176D-1B11-4507-9E97-FC8A5C9C7194
        if len(mac_addresses) == 0 and not re.match("^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$", device_id):
            errors.append("Device ID is not a valid UUID!")

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
                comp = models.Computer(name=name, description=description, device_id=device_id, source_id=source_id, last_logon_name="", ignore_av_check=ignore_av_check)
                db.session.add(comp)
                db.session.flush()
                id = comp.id
                mongo.add_to_audit_trail(g.oidc_id_token['preferred_username'], "Adding manual computer " + name, "Ignore compliance check: " + str(ignore_av_check))
            # edit existing computer
            else:
                comp = models.Computer.query.filter_by(id=id).first()
                comp.name = name
                comp.description = description
                comp.device_id = device_id
                comp.ignore_av_check = ignore_av_check
                models.MacAddress.query.filter_by(comp_id=id).delete()
                mongo.add_to_audit_trail(g.oidc_id_token['preferred_username'], "Editing manual computer " + name,
                                         "Ignore compliance check: " + str(ignore_av_check))
            for mac_address in mac_addresses:
                mac_address = mac_address.replace(":", "").replace("-", "").replace(".", "").upper()
                mac = models.MacAddress(comp_id=id, mac=mac_address)
                db.session.add(mac)
            db.session.commit()

            # lets reset the form values
            id = ""
            name = ""
            description = ""
            device_id = ""
            ignore_av_check = False
            originals = []
        elif len(errors) > 0 and id.isdigit():
            action = "edit"
    else:
        id = ""
        name = ""
        description = ""
        device_id = ""
        ignore_av_check = False

    form.name.data = name
    form.description.data = description
    form.device_id.data = device_id
    if len(originals) == 0:
        originals.append("")
    if asc_or_desc == "asc":
        computers = models.Computer.query.order_by(order_by).all()
    else:
        computers = models.Computer.query.order_by(desc(order_by)).all()

    show_sccm_button = app.config.get('SCCM_SHOW_BUTTON', False)
    pacs_file = app.config['PACS_STATUS_FILE']
    if os.path.isfile(pacs_file):
        pacs_enabled = False
    else:
        pacs_enabled = True

    return render_template('index.html', form=form, errors=errors, mac_addresses=originals, computers=computers,
                           action=action, id=id, ignore_av_check=ignore_av_check,
                           logon=g.sso_identity, order_by=order_by, asc_or_desc=asc_or_desc,
                           show_sccm_button=show_sccm_button, show_pacs_button=True, pacs_enabled=pacs_enabled,
                           show_home_button=False, show_logs_button=True, version=app.config['VERSION'])

@app.route('/delete/<int:computer_id>', methods=['POST'])
@oidc.require_login
def delete_computer(computer_id):
    mongo = mongo_handler()
    errors = []
    if len(errors) > 0:
        return jsonify({"success": False, "errors": errors })
    else:
        models.MacAddress.query.filter_by(comp_id=computer_id).delete()
        comp = models.Computer.query.filter_by(id=computer_id)
        try:
            name = comp.first().name
        except:
            name = "Computer not found!"
        comp.delete()
        db.session.commit()
        mongo.add_to_audit_trail(g.oidc_id_token['preferred_username'], "Deleting manual computer " + name,
                                 "Succeeded")

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
    mongo = mongo_handler()
    errors = []
    if len(errors) == 0:
        pacs_file = app.config['PACS_STATUS_FILE']
        if os.path.isfile(pacs_file):
            os.remove(pacs_file)
            mongo.add_to_audit_trail(g.oidc_id_token['preferred_username'], "Enabled system wide compliance check!", "Succeeded")
            message = "Enabled compliance check for PACS!\n"
        else:
            Path(pacs_file).touch()
            mongo.add_to_audit_trail(g.oidc_id_token['preferred_username'], "Disabled system wide compliance check!", "Succeeded")
            message = "Disabled compliance check for PACS!\n"
    else:
        message = "Not going to do this!\n"
        for error in errors:
            message = message + error + "\n"

    return jsonify({"message": message })

@app.route("/logout")
def logout():
    oidc.logout()
    return redirect(app.config['LOGOUT_REDIRECT'])

@app.route('/sccm_import', methods=['POST'])
@oidc.require_login
def sccm_import():
    mongo = mongo_handler()
    if app.config['SCCM_SHOW_BUTTON']:
        errors = []
        if len(errors) == 0:
            # avoid threading issues on WIndows
            if system == 'Windows':
                pythoncom.CoInitialize()
            mongo.add_to_audit_trail(g.oidc_id_token['preferred_username'], "SCCM Import initiated", "busy")
            sccm_import = import_handler()
            message = sccm_import.import_from_sccm_and_ad()
            mongo.add_to_audit_trail(g.oidc_id_token['preferred_username'], "SCCM Import finalized", "done")
        else:
            message = "Import failed!\n"
            for error in errors:
                message = message + error + "\n"

        return jsonify({"message": message })
