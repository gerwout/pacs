import argparse, sys, requests, json
from app import app
from app.utils.mongo_handler import mongo_handler
from itsdangerous import (TimedJSONWebSignatureSerializer, SignatureExpired, BadSignature)

def generate_auth_token(json_dict, expiration=600):
    s = TimedJSONWebSignatureSerializer(app.config.get("SECRET_API_KEY"), expires_in=expiration)

    return s.dumps(json_dict).decode('utf-8')

def verify_api_auth_token(token, expiration=600):
    s = TimedJSONWebSignatureSerializer(app.config.get("SECRET_API_KEY"), expires_in=expiration)
    try:
        data = s.loads(token)
    except SignatureExpired:
        return False, "Signature is valid, but is has been expired!"  # valid token, but expired
    except BadSignature:
        return False, "Bad signature, is it signed by a different secret key?"  # invalid token

    return True, data

def main():
    parser = argparse.ArgumentParser(description='Test the PACS compliance check end point')
    parser.add_argument('--action', required=False, help='Action can be get_log_ids_for_user or test_log_id')
    parser.add_argument('--user', required=False, help='User name', default="")
    parser.add_argument('--limit', required=False, help='maximum of records to return, defaults to 10', type=int, default=10)
    parser.add_argument('--logid', required=False, help='log_id to replay', default="")
    parser.add_argument('--url', required=False, help='Url to compliance check', default="http://127.0.0.1:5000/check-compliance")
    # show help when no arguments are given
    if len(sys.argv) == 1:
        parser.print_help(sys.stdout)
        sys.exit(0)

    args = parser.parse_args()
    action = args.action
    user = args.user
    limit = args.limit
    logid = args.logid
    url = args.url

    mongo = mongo_handler()
    if action == "get_log_ids_for_user":
        logs = mongo.get_all_log_ids_for_user(user, limit)
        print("There are " + str(logs.count()) + " logs found.")
        for idx, log in enumerate(logs):
            print(log['_id'])
    elif action == "test_log_id":
        log = mongo.get_log_id(logid)
        if log.count() == 0:
            print("There is no log for the given logid!")
        else:
            log_dict = log[0]
            del log_dict['_id']
            del log_dict['timestamp']
            print("Log id details: ")
            print(log_dict)
            token = generate_auth_token(log_dict)
            auth_token_dict = {"auth_token": token}
            print("Going to POST JSON: " + str(auth_token_dict))
            try:
                r = requests.post(url, json=auth_token_dict, timeout=15)
            except Exception as e:
                print("Could not post to the compliance url, got the following error:")
                print(str(e))
                exit(0)

            status_code = r.status_code
            print("Got a " + str(status_code) + " response.")
            if status_code == 200:
                data = r.json()
                print ("Got a JSON response :-)")
                print(data)
                print("Going to validate the JSON auth token response")
                res, data = verify_api_auth_token(data['auth_token'])
                if not res:
                    print("JSON signature error!")
                else:
                    print("Decoded JSON: ")
                    print(data)
            else:
               print("Raw response: ")
               print(r.content.decode('utf-8'))

if __name__ == "__main__":
    main()