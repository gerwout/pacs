import os
import configparser
import platform
system = platform.system()
# basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    OIDC_SCOPES = ["openid", "email", "profile"]
    TREAT_AS_BOOLEAN = ["oidc_cookie_secure", "ldap_require_valid_cert", "sccm_show_button"]
    VERSION = "0.1b"

    @classmethod
    def read_config(cls):
        if system == 'Windows':
            dir_path = os.path.dirname(os.path.realpath(__file__))
            config_file = dir_path + "/config.ini"
        else:
            config_file = "/etc/pacs/config.ini"

        try:
            f = open(config_file, "r")
            content = f.read()
        except:
            print("Could not open configuration file " + config_file)
            exit(0)

        config = configparser.ConfigParser()
        config.read_string(content)
        for section in config.sections():
            for option in config.options(section):
                if option not in Config.TREAT_AS_BOOLEAN:
                    value = config.get(section, option)
                else:
                    value = config.getboolean(section, option)
                setattr(cls, option.upper(), value)


