import requests
from itsdangerous import TimedJSONWebSignatureSerializer, BadSignature, SignatureExpired
import configparser, os
from pritunl import logger
from pritunl.host.host import Host
from pritunl.server.server import Server
from pritunl.organization.organization import Organization

import json

def get_configuration():
    dir_path = os.path.dirname(os.path.realpath(__file__))
    config_file = dir_path + "/config.ini"

    try:
        f = open(config_file, "r")
        content = f.read()
    except:
        print("Could not open configuration file " + config_file)
        exit(0)

    config = configparser.ConfigParser()
    config.read_string(unicode(content, 'utf-8'))

    return config

def generate_auth_token(json_dict, expiration=600):
    s = TimedJSONWebSignatureSerializer(config.get("general", "API_SECRET_KEY"), expires_in=expiration)

    return s.dumps(json_dict)

def verify_api_auth_token(token):
    s = TimedJSONWebSignatureSerializer(config.get("general", "API_SECRET_KEY"))
    try:
        data = s.loads(token)
    except SignatureExpired:
        return False  # valid token, but expired
    except BadSignature:
        return False  # invalid token

    return data


# [SYNCHRONOUS] Called on user connect must return True or False to allow
# connection and None if allowed or a string with reason if not allowed.
def user_connect(host_id, server_id, org_id, user_id, host_name,
        server_name, org_name, user_name, remote_ip, mac_addr, platform, device_id, device_name, password, **kwargs):
    host = Host(id=host_id).dict()
    server = Server(id=server_id).dict()
    org = Organization(id=org_id)
    user = org.get_user(user_id).dict()
    org = org.dict()
    server_has_ip6 = server.get('ipv6', False)
    server_protocol = str(server.get('protocol', ""))
    server_port = str(server.get('port', ""))
    server_name = str(server.get('name', ""))
    server_status = str(server.get('status', ""))
    host_ip6 = str(host.get('local_addr6', ""))
    host_ip4 = str(host.get('local_addr', ""))
    host_connect_ip = str(host.get('public_addr', ""))
    host_name = str(host.get('name', "")).upper()
    user_name = str(user.get('name', ""))
    user_has_pin = str(user.get('pin', False))
    user_is_disabled = str(user.get('disabled', False))
    user_email = str(user.get('email', ""))
    org_name = str(org.get('name', ""))

    json_dict = {"host_id": host_id, "server_id": str(server_id), "org_id": str(org_id), "user_id": str(user_id), "host_name": host_name,
                 "server_name": server_name, "org_name": org_name, "user_name": user_name, "remote_ip": remote_ip,
                 "mac_addr": mac_addr, "platform": platform, "device_id": device_id, "device_name": device_name, "server_has_ip6": server_has_ip6,
                 "server_protocol": server_protocol, "server_port": server_port, "server_status": server_status, "host_ip6": host_ip6,
                 "host_ip4": host_ip4, "host_connect_ip": host_connect_ip, "user_has_pin": user_has_pin, "user_disabled": user_is_disabled,
                 "user_email": user_email}

    token = generate_auth_token(json_dict)
    auth_token_dict = {"auth_token": token}
    try:
        r = requests.post(config.get("general", "COMPLIANCE_URL"), json=auth_token_dict, timeout=15)
        if r.status_code != 200:
            # when we encounter an error, we assume that we are compliant
            return True, "Got a non HTTP 200 OK response from " + config.get("general", "COMPLIANCE_URL") + "(code: )" + str(r.status_code)
        else:
            data = r.json()
            return_data = verify_api_auth_token(data['auth_token'])
            if not return_data:
                return False, "Auth token is not valid or has expired"
            else:
                return return_data['compliant'], None
    except:
        # when we encounter an error, we assume that we are compliant
        return True, None

config = get_configuration()