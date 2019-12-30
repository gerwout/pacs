import requests
from itsdangerous import TimedJSONWebSignatureSerializer, BadSignature, SignatureExpired
import configparser, os
from pritunl import logger

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
    host_name = host_name.upper()

    json_dict = {"host_id": host_id, "server_id": str(server_id), "org_id": str(org_id), "user_id": str(user_id), "host_name": host_name,
                 "server_name": server_name, "org_name": org_name, "user_name": user_name, "remote_ip": remote_ip,
                 "mac_addr": mac_addr, "platform": platform, "device_id": device_id, "device_name": device_name}

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