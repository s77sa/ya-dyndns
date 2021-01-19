#!/home/seven/Projects/py-venv/bin/python3
import io
import os
import requests
import sys
import json
import datetime
from requests.auth import AuthBase
from collections import defaultdict


################# Do not edis this variables #############
EXTERNAL_CHECKIP_SITE = "http://api.ipify.org?format=json"
ALL_PARAM_DICT = {'url_list':'','url_edit':'', 'token':'', 'domain':'', 'subdomain':'', 'subdomainid':'', 'ip':'', 'ttl':''}
# LOG_MESSTYPE_ERR = "ERROR"
# LOG_MESSTYPE_WARN = "WARRNING"
# LOG_MESSTYPE_INFO = "INFO"
MESSTYPE = defaultdict(lambda: 'NULL', {'err':'ERROR','warn':'WARRNING','inf':'INFO'})
##########################################################

################# Editable variables #####################
Log_Path = "/home/seven/Projects/dyn-test.log"
#Config_File = None
Config_File = "/home/seven/Projects/ya-dyndns.json"
ExternalIP = None
ALL_PARAM_DICT['domain'] = None # FQDN main domain
ALL_PARAM_DICT['subdomain'] = None # FQDN sub domain
ALL_PARAM_DICT['ttl'] = None # TTL for sub domain
ALL_PARAM_DICT['url_list'] = None # Yandex Pdd Url for list
ALL_PARAM_DICT['url_edit'] = None # Yandex Pdd Url for edit
ALL_PARAM_DICT['url_add'] = None # Yandex Pdd Url for add record
ALL_PARAM_DICT['token'] = None # Yandex Pdd Token

# ALL_PARAM_DICT['domain'] = "???????????" # FQDN main domain
# ALL_PARAM_DICT['subdomain'] = "??????????" # FQDN sub domain
# ALL_PARAM_DICT['ttl'] = 1800 # TTL for sub domain
# ALL_PARAM_DICT['url_list'] = "https://pddimp.yandex.ru/api2/admin/dns/list" # Yandex Pdd Url for list
# ALL_PARAM_DICT['url_edit'] = "https://pddimp.yandex.ru/api2/admin/dns/edit" # Yandex Pdd Url for edit
# ALL_PARAM_DICT['url_add'] = "https://pddimp.yandex.ru/api2/admin/dns/add" # Yandex Pdd Url for add record
# ALL_PARAM_DICT['token'] = "???????????????????????" # Yandex Pdd Token
##########################################################

# ############### API Help links #########################
# https://connect.yandex.ru/portal/services/webmaster/resources/
# https://yandex.ru/dev/connect/directory/api/about.html


def WriteLog (Text, Log_MessType):
    try:
        file = open(Log_Path, "a")
        line = datetime.datetime.strftime(datetime.datetime.now(), "%Y.%m.%d %H:%M:%S") + "\t" + Log_MessType + "\t" + Text
        file.write(line + "\n")
        file.close()
        return True
    except Exception as e:
        print("Error writing to log.\n" + str(e))
        sys.exit(1)


class TokenAuth(AuthBase):
    def __init__(self, token):
        self.token = token
 
    def __call__(self, r):
        r.headers["PddToken"] = f"{self.token}" 
        return r
# Read JSON needded for ReadParametersFromConfig() 
def ReadJsonConfig(Config):
    if (os.path.exists(Config)):
        file = open(Config, "r")
        j = json.load(file)
        file.close()
        # print(j)
        return j
    else:
        return None

# Read parameters from config file
def ReadParametersFromConfig(PathToConfig):
    WriteLog("Load config: " + PathToConfig, MESSTYPE['inf'])
    if (os.path.exists(PathToConfig)):
        j = ReadJsonConfig(PathToConfig)
        ALL_PARAM_DICT['domain'] = j.get("YandexFqdnMainDomain") # FQDN main domain
        ALL_PARAM_DICT['subdomain'] = j.get("YandexFqdnSubDomain") # FQDN sub domain
        ALL_PARAM_DICT['ttl'] = j.get("SubDomainTtl") # TTL for sub domain
        ALL_PARAM_DICT['url_list'] = j.get("YandexPddAdressList") # Yandex Pdd Url for list
        ALL_PARAM_DICT['url_edit'] = j.get("YandexPddAdressEdit") # Yandex Pdd Url for edit
        ALL_PARAM_DICT['url_add'] = j.get("YandexPddAdressAdd") # Yandex Pdd Url for add record
        ALL_PARAM_DICT['token'] = j.get("YandexPddToken") # Yandex Pdd Token
    else:
        WriteLog("Config not exists from path: " + PathToConfig, MESSTYPE['err'])

# Open input JSON Config file
def OpenConfigFile(PathToLog):
    if (os.path.exists(str(PathToLog))):
        WriteLog("Entered log file: " + str(PathToLog), MESSTYPE['inf'])
        ReadParametersFromConfig(PathToLog)
    else:
        WriteLog("Error working whith log file: " + PathToLog)

# Check input parameters
def CheckAllParams(PARAM_DICT):
    status = True
    for param in PARAM_DICT:
        if(PARAM_DICT[param] == None or PARAM_DICT[param] == ''):
            status = False
    return status

# Get IP from external WEB site
def GetExternalIP(url):
     response = requests.get(url)
     if(response.status_code == 200):
        #  print(response.content.decode("UTF-8"))
         j = json.loads(response.content.decode("UTF-8"))
         ip_str = j.get("ip")
         WriteLog("IP from external site: " + ip_str, MESSTYPE['inf'])
         return(ip_str)
     else:
        WriteLog("Error request from: "+ response.url, MESSTYPE['err'])
        return None


# Get All information from Yandex DNS Information
def GetYandexDnsList(url_list, domain, token):
    response = requests.get(
        url_list,
        auth=TokenAuth(token),
        params={"domain": domain}
    )
    if (response.status_code == 200):
        j = json.loads(response.content.decode("UTF-8"))
        if (j.get("success") == "ok"):
            return j
    else:
        return None     

# Get IP adn ID from all contents
def GetIPSubDomain(jsoncontent, subdomain):
    subip = None
    subid = None
    # print(jsoncontent)
    # print(subdomain)
    if (jsoncontent != None):
        for line in jsoncontent.get("records"):
            # print(line.get("fqdn"))
            if (line.get("fqdn") == subdomain):
                subip = line.get("content")
                subid = line.get("record_id")
                # print(subip, subid)
        return {"SubDomainIP":subip, "SubDomainID":subid}
    else:
        return None


def EditDNSRecord(PARAM_DICT, record_id, content):
    status = 0
    response = requests.post(
        PARAM_DICT['url_edit'],
        auth=TokenAuth(PARAM_DICT['token']),
        params={
            "domain": PARAM_DICT['domain'],
            "record_id": record_id,
            #"subdomain":subdomain,
            "content":content,
            "ttl":PARAM_DICT['ttl']}
    )
    if (response.status_code == 200):
        j = json.loads(response.content.decode("UTF-8"))
        if (j.get("success") == "ok"):
            WriteLog("Successfull edit DNS record: " + PARAM_DICT['subdomain'] + "\tIP: " + ExternalIP, MESSTYPE['inf'])
            return j
    else:
        WriteLog("Error edit DNS record: " + PARAM_DICT, MESSTYPE['err'])
        WriteLog(response, MESSTYPE['err'])
        return response
        


def CreateDNSRecord(PARAM_DICT, record_type, content):
    status = 0
    # print(PARAM_DICT['subdomain'].partition('.')[0])
    # print(CheckAllParams(PARAM_DICT))
    response = requests.post(
        PARAM_DICT['url_add'],
        auth=TokenAuth(PARAM_DICT['token']),
        params={
            "domain": PARAM_DICT['domain'],
            "type": record_type,
            "subdomain":PARAM_DICT['subdomain'].partition('.')[0],
            "content":content,
            "ttl":PARAM_DICT['ttl']}
    )
    if (response.status_code == 200):
        j = json.loads(response.content.decode("UTF-8"))
        if (j.get("success") == "ok"):
            WriteLog("Successfully creating DNS record: " + PARAM_DICT['subdomain'] + ' whith IP: ' + content, MESSTYPE['inf'])
            return j
    else:
        WriteLog(response, MESSTYPE['err'])
        return response



WriteLog("============== Init ==============", MESSTYPE['inf'])

if (len(sys.argv[1:]) > 0):
    Config_File = (sys.argv[1:])
    OpenConfigFile(Config_File)
else:
    if(Config_File != None):
        OpenConfigFile(Config_File)
    else:
        if (CheckAllParams(ALL_PARAM_DICT) != True):
                WriteLog("One or any input paramters not setted", MESSTYPE['err'])
                sys.exit(1)

ExternalIP = GetExternalIP(EXTERNAL_CHECKIP_SITE)

ExternalContent = (GetYandexDnsList(ALL_PARAM_DICT['url_list'], ALL_PARAM_DICT['domain'], ALL_PARAM_DICT['token']))

SubDomainInfo = (GetIPSubDomain(ExternalContent, ALL_PARAM_DICT['subdomain']))
if(SubDomainInfo['SubDomainID'] == None):
    # print(ALL_PARAM_DICT)
    # Create Sub Domain
    CreateDNSRecord(ALL_PARAM_DICT, 'A', ExternalIP)
    # print("if create")
    # print(SubDomainInfo['SubDomainID'])
    # print(SubDomainInfo['SubDomainID'])
else:
        # Compare IP
    if (SubDomainInfo['SubDomainIP'] == ExternalIP):
        WriteLog("Compare External IP and SubDomain IP SUCCESSFULLY: " + ExternalIP, MESSTYPE['inf'])
    else:
        # Set IP
        EditDNSRecord(ALL_PARAM_DICT, SubDomainInfo['SubDomainID'], ExternalIP)

WriteLog("=============== End ===============", MESSTYPE['inf'])


