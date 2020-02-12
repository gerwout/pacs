from app import app
from pymongo import MongoClient, DESCENDING
from datetime import datetime
import pprint

class mongo_handler():
    client = None
    db = None

    def __init__(self):
        self.client = MongoClient(app.config['MONGO_DB_URI'])
        self.db = self.client[app.config['MONGO_DB_NAME']]
        self.create_index_for_logs()
        self.create_index_for_audit_trail()

    def create_index_for_audit_trail(self):
        if len(self.db.audittrail.index_information()) == 0:
            self.db.audittrail.create_index("timestamp")
            self.db.audittrail.create_index("user")
            self.db.audittrail.create_index("action")

    def create_index_for_logs(self):
        if len(self.db.logs.index_information()) == 0:
            self.db.logs.create_index("host_name")
            self.db.logs.create_index("server_name")
            self.db.logs.create_index("org_name")
            self.db.logs.create_index("user_name")
            self.db.logs.create_index("remote_ip")
            self.db.logs.create_index("user_email")
            self.db.logs.create_index("mac_addr")
            self.db.logs.create_index("platform")
            self.db.logs.create_index("device_name")
            self.db.logs.create_index("host_ip4")
            self.db.logs.create_index("host_connect_ip")
            self.db.logs.create_index("timestamp")

    def add_to_logs(self, dictionary):
        result = self.db.logs.insert_one(dictionary)

        return result.inserted_id

    def add_to_audit_trail(self, user, action, result):
        timestamp = datetime.now().timestamp()
        self.db.audittrail.insert_one({"timestamp":timestamp, "user":user, "action":action, "result":result})

    def get_all_logs(self, start=None, end=None, user="", mac="", ip=""):
        if start == None:
            start = datetime.timestamp(datetime(datetime.now().year, datetime.now().month, datetime.now().day, 0, 0, 1))
        else:
            start = datetime.timestamp(start)
        if end == None:
            end = datetime.timestamp(datetime(datetime.now().year, datetime.now().month, datetime.now().day, 23, 59, 59))
        else:
            end = datetime.timestamp(end)

        search_dict = {"timestamp":{"$gte": start, "$lte": end}}
        if user != "":
            search_dict['user_name'] = user
        if mac != "":
            search_dict['mac_addr'] = mac
        if ip != "":
            search_dict['remote_ip'] = ip

        return self.db.logs.find(search_dict).sort("timestamp", DESCENDING)

    def get_audit_trail(self, start=None, end=None, user=""):
        if start == None:
            start = datetime.timestamp(datetime(datetime.now().year, datetime.now().month, datetime.now().day, 0, 0, 1))
        else:
            start = datetime.timestamp(start)
        if end == None:
            end = datetime.timestamp(datetime(datetime.now().year, datetime.now().month, datetime.now().day, 23, 59, 59))
        else:
            end = datetime.timestamp(end)

        search_dict = {"timestamp":{"$gte": start, "$lte": end}}
        if user != "":
            search_dict['user'] = user

        return self.db.audittrail.find(search_dict).sort("timestamp", DESCENDING)

    def get_unique_users(self):
        audit_list = self.db.audittrail.find({}).distinct("user")
        logs_list = self.db.logs.find({}).distinct("user_name")

        return sorted(audit_list + list(set(logs_list) - set(audit_list)))

    def get_unique_macs(self):
        return self.db.logs.find({}).sort("mac_addr").distinct("mac_addr")

    def get_unique_ips(self):
        return self.db.logs.find({}).sort("remote_ip").distinct("remote_ip")