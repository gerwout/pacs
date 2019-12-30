from app import app, models
import jwt
import uuid
import requests
import json
from datetime import datetime, timedelta

class cylance():

    access_token = ""
    def check_compliance(self, data):
        mac_address = data['mac_addr'].replace(":", "").replace("-", "").replace(".", "").upper()

        try:
            mac = models.MacAddress.query.filter_by(mac=mac_address).first()
            comp_id = mac.comp_id
        except:
            # can not seem to find this computer
            return False

        computer = models.Computer.query.filter_by(id=comp_id).first()
        ignore_av_check = computer.ignore_av_check

        # when we manually set that we want to ignore the AV compliance check, we assume that the system is compliant
        if ignore_av_check:
            return True

        self.access_token = self.__authenticate_to_cylance()
        # Cylance api not available, assume compliant
        if self.access_token == "DOWN":
            return True
        # we failed to get an access token, assume non compliant
        if not self.access_token:
            return False

        # we do need to query all available mac addresses for that system.
        # when you start with -for example- a wireless connection, Cylance will register the wireless mac address
        # if the user decides to connect later on with a cabled connection, the mac address update is not performed
        # instantly. Therefore we need to query all the mac addresses from the affected system
        all_mac_addresses = models.MacAddress.query.filter_by(comp_id=comp_id).all()
        ret_value = False
        for m in all_mac_addresses:
            if self.__check_mac_address_registered(m.mac):
                ret_value = True
                break;

        return ret_value

    def __authenticate_to_cylance(self):
        # access token will be valid for 1 minute
        timeout = 60
        now = datetime.utcnow()
        timeout_datetime = now + timedelta(seconds=timeout)
        epoch_time = int((now - datetime(1970, 1, 1)).total_seconds())
        epoch_timeout = int((timeout_datetime - datetime(1970, 1, 1)).total_seconds())
        jti_val = str(uuid.uuid4())

        AUTH_URL = app.config['CYLANCE_APP_HOST'] + "/auth/v2/token"

        claims = {
            "exp": epoch_timeout,
            "iat": epoch_time,
            "iss": "http://cylance.com",
            "sub": app.config['CYLANCE_APP_ID'],
            "tid": app.config['CYLANCE_TENANT_ID'],
            "jti": jti_val,
            "scp": "device:read"
        }

        # encoded is basically your auth token
        encoded = jwt.encode(claims, app.config['CYLANCE_APP_SECRET'], algorithm='HS256').decode('utf-8')
        payload = {"auth_token": encoded}
        headers = {"Content-Type": "application/json; charset=utf-8"}
        try:
            resp = requests.post(AUTH_URL, headers=headers, data=json.dumps(payload), timeout=20)
        except:
            # logger.info('Cylance auth token call failed!', 'plugin')
            # if the Cylance API experiences troubles, we return that it is down, we will assume that you are compliant to avoid availability concerns
            return "DOWN"
        if (resp.status_code == 200):
            return json.loads(resp.text)['access_token']
        else:
            return False

    def __check_mac_address_registered(self, mac_address):
        # lets unify the format first
        mac_address = mac_address.upper()
        mac_address = ':'.join([i + j for i, j in zip(mac_address[::2], mac_address[1::2])])
        mac_url = app.config['CYLANCE_APP_HOST'] + "/devices/v2/macaddress/" + mac_address
        headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + self.access_token}

        try:
            resp = requests.get(mac_url, headers=headers, timeout=2)
        except:
            # if the Cylance API experiences troubles, we assume that you are compliant to avoid an availability concern
            return True

        machines = json.loads(resp.text)
        if isinstance(machines, list):
            for machine in machines:
                state = machine["state"]
                is_safe = machine["is_safe"]
                name = machine["name"]
                if state == "Online" and is_safe:
                    return True
            return False
        else:
            return False