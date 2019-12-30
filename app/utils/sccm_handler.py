import platform
system = platform.system()
if system == 'Windows':
    import wmi
else:
    import wmi_client_wrapper as wmi

class sccm_handler():
    sccm_host = ""
    sccm_user = ""
    sccm_pass = ""
    sccm_namespace = ""

    def __init__(self, sccm_host, sccm_user, sccm_pass, sccm_namespace):
        self.sccm_host = sccm_host
        self.sccm_user = sccm_user
        self.sccm_pass = sccm_pass
        self.sccm_namespace = sccm_namespace

    def get_all_systems(self):
        systems = []
        wql = "select SMS_R_System.Name, SMS_R_System.LastLogonUserName, SMS_R_System.MACAddresses from SMS_R_System"
        if system == 'Windows':
            c = wmi.WMI(self.sccm_host, namespace=self.sccm_namespace, user=self.sccm_user, password=self.sccm_pass)
            all_systems = c.query(wql)

            for s in all_systems:
                try:
                    mac_addresses = list(s.MACAddresses)
                except:
                    mac_addresses = []

                systems.append({"Name": s.Name, "LastLogonUserName": s.LastLogonUserName, "MACAddresses": mac_addresses})
        else:
            c = wmi.WmiClientWrapper(username=self.sccm_user, password=self.sccm_pass, host=self.sccm_host,
                                     namespace=self.sccm_namespace)
            all_systems = c.query(wql)
            for s in all_systems:
                if isinstance(s['MACAddresses'], list):
                    mac_addresses = s['MACAddresses'][0].split(",")
                else:
                    mac_addresses = []
                systems.append({"Name": s['Name'], "LastLogonUserName": s['LastLogonUserName'], "MACAddresses": mac_addresses})

        return systems