import ldap, re, sys, json
from app import app

class ldap_handler():

    ldap_conn = None

    def connect_and_bind_to_ldap(self, ldap_host, ldap_user, ldap_pass):
        error_msg = False
        conn = None

        try:
            result = re.match("^(?P<protocol>ldap[s]{0,1})://(?P<hostname>.*)$", ldap_host)
            protocol = result.group('protocol')
        except:
            print("LDAP_HOST needs to start with ldap:// or ldaps:// and it needs to be a valid hostname")
            print("i.e. ldaps://exampledomain.local:3269")
            print("i.e. ldap://exampledomain.local:3268")
            exit()

        if not app.config['LDAP_REQUIRE_VALID_CERT']:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        else:
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, app.config['LDAP_CA_CERT_ISSUER'])

        try:
            conn = ldap.initialize(ldap_host)
        except ldap.LDAPError as e:
            error_msg = str(e)
        try:
            if protocol == "ldap":
                conn.start_tls_s()
        except ldap.CONNECT_ERROR as e:
            error_msg = str(e)
        try:
            conn.simple_bind_s(ldap_user, ldap_pass)
        except (ldap.SERVER_DOWN, ldap.LDAPError) as e:
            error_msg = str(e)

        self.ldap_conn = conn

        return error_msg

    def search_ldap(self, base_dn, search_filter):
        try:
            ldap_result_id = self.ldap_conn.search(base_dn, ldap.SCOPE_SUBTREE, search_filter)
            result_set = []
            while 1:
                result_type, result_data = self.ldap_conn.result(ldap_result_id, 0)
                if (result_data == []):
                    break
                elif result_type == ldap.RES_SEARCH_ENTRY:
                    result_set.append(result_data)
            return result_set
        except ldap.LDAPError as e:
            if type(e.message) == dict:
                if e.message.has_key('desc'):
                    print(e.message['desc'])
                if e.message.has_key('info'):
                    print(e.message['info'])
                sys.exit()

    def get_all_computers(self, base_dn):
      search_filter = "(&(objectCategory=computer))"
      result = self.search_ldap(base_dn, search_filter)

      return result