from app.utils.ldap_handler import ldap_handler
from app.utils.sccm_handler import sccm_handler
from app import app
from app import db
from app import models

class import_handler():

    def import_from_sccm_and_ad(self):
        ldap = ldap_handler()
        error_msg = ldap.connect_and_bind_to_ldap(app.config['LDAP_END_POINT'], app.config['LDAP_USER'], app.config['LDAP_PASS'])
        if error_msg:
            return error_msg

        all_computers = ldap.get_all_computers(app.config['LDAP_SEARCH_START'])
        computers = {}
        for computer in all_computers:
            name = computer[0][1].get('name', b'')[0].upper().decode('utf-8')
            description = computer[0][1].get('description', '')
            if isinstance(description, list):
                description = description[0].decode('utf-8')
            computers[name] = {}
            computers[name]['description'] = description

        result = models.Source.query.filter_by(name='external').first()
        source_id = result.id

        # we are going to check the current "external" computers that have the compliance check disabled
        # when we are re-importing the same system we want to retain the current setting
        current_comps_with_no_compliance = models.Computer.query.filter_by(source_id=source_id, ignore_av_check=True)

        temp_dict = {}
        for comp in current_comps_with_no_compliance:
            name = comp.name
            comp_id = comp.id
            macs = models.MacAddress.query.filter_by(comp_id=comp_id)
            temp_dict[name] = []
            for mac in macs:
                m = ':'.join(mac.mac[i:i + 2] for i in range(0, len(mac.mac), 2))
                temp_dict[name].append(m)

        comp_keys = temp_dict.keys()
        for computer in models.Computer.query.filter_by(source_id=source_id):
            models.MacAddress.query.filter_by(comp_id=computer.id).delete()
            models.Computer.query.filter_by(id=computer.id).delete()

        count = 0
        ignore_compliance_count = 0
        sccm = sccm_handler(app.config['SCCM_END_POINT'], app.config['SCCM_USER'], app.config['SCCM_PASS'],
                            app.config['SCCM_NAME_SPACE'])
        sccm_computers = sccm.get_all_systems()
        for item in sccm_computers:

            if item.get("MACAddresses", None) is not None:
                count = count + 1
                last_logon_name = "-" if item.get("LastLogonUserName", None) is None else item.get("LastLogonUserName", None)
                name = "" if item.get("Name", None) is None else item.get("Name", None).upper()
                description = computers[name]['description'] if name in computers else "Not in active directory!"

                # ok, we have a potential match for a system that currently has the compliance check disabled
                if name in comp_keys:
                    ignore_av_check = True
                    for mac in item["MACAddresses"]:
                        if mac not in temp_dict[name]:
                            ignore_av_check = False
                            break
                else:
                    ignore_av_check = False

                if ignore_av_check:
                    ignore_compliance_count = ignore_compliance_count + 1

                comp = models.Computer(name=name, description=description, source_id=source_id,
                                       last_logon_name=last_logon_name, ignore_av_check=ignore_av_check)
                db.session.add(comp)
                db.session.flush()
                id = comp.id
                for mac_address in item["MACAddresses"]:
                    mac_address = mac_address.replace(":", "").replace("-", "").replace(".", "").upper()
                    if mac_address not in models.MacAddress.ignore_mac_list:
                        mac = models.MacAddress(comp_id=id, mac=mac_address)
                        db.session.add(mac)
        db.session.commit()
        message = "Imported " + str(count) + " systems from SCCM -> PACS.\n"
        message = message + "There are " + str(ignore_compliance_count) + " imported systems that don't have a compliance check."

        return message