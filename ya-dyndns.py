#!/usr/bin/python3
import io
import os
import requests
import sys
import json
import datetime
from requests.auth import AuthBase
from collections import defaultdict
import tarfile
from pythonping import ping

################# Do not edis this variables #############
EXTERNAL_CHECKIP_SITE = "http://api.ipify.org?format=json"
ALL_PARAM_DICT = {'url_list':'','url_edit':'', 'token':'', 'domain':'', 'subdomain':'', 'subdomainid':'', 'ip':'', 'ttl':''}
MESSTYPE = defaultdict(lambda: 'NULL', {'err':'ERROR','warn':'WARRNING','inf':'INFO', 'dbg': 'DEBUG'})
##########################################################

################# Editable variables #####################
Log_Path = "./dyn-test.log"
Log_To_Stdout = True # True or False
Log_Max_Size = 5242880 # Bytes 
Log_GZ_Count = 5 # Max GZ archived log files
Log_Level = 2 # 0 - disable log, 1 - only error, 2 - error and warning, 3 - error, warning and info, 4 - all
Config_File = "./ya-dyndns.json"
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


def LogToTar(PathToLog, gz_count):
    if(os.path.exists(PathToLog)):
        tar = tarfile.open(PathToLog+"."+str(gz_count + 1)+".gz", "w:gz")
        tar.add(PathToLog)
        tar.close()
        # Delete current log file
        os.remove(PathToLog)

def LogRotate(PathToLog):
    list_files = {}
    gz_count = 0
    if(os.path.exists(PathToLog)):
        if (os.path.getsize(PathToLog) > Log_Max_Size):
            # Archive current log file
            LogToTar(os.path.realpath(PathToLog), gz_count)
            dir_name = (os.listdir(os.path.dirname(PathToLog)))
            # Search all archived log files for delete old
            for file_name in dir_name:
                if (file_name.find("gz",0,len(file_name))) > 0:
                    try:
                        list_files.update({file_name:datetime.datetime.fromtimestamp(os.path.getctime(file_name))})
                        curr_count = int(file_name.rpartition('log.')[2].partition('.gz')[0])
                        if curr_count > gz_count:
                            gz_count = curr_count
                        # print(file_name.rpartition('.gz')[0])
                    except Exception as e:
                        print("Error working whith log archives.\n" + str(e))

        sorted_list_files = sorted(list_files.items(), key=lambda x:x[1])
        sorted_list_files.reverse()
        i_count = 0
        for item in sorted_list_files:
            i_count += 1
            if(i_count >= Log_GZ_Count):
                # Delete old archive logs
                print("Delete old log file: " + os.path.realpath(item[0]))
                os.remove(os.path.realpath(item[0]))

# print(Log_Path)
# LogRotate(Log_Path)
# sys.exit(0)

def LogWriteToFile(textline):
    if (Log_To_Stdout):
        print(textline)

    try:
        file = open(Log_Path, "a")
        file.write(textline + "\n")
        file.close()
        LogRotate(Log_Path) # Log rotate 
        return True
    except Exception as e:
        print("Error writing to log.\n" + str(e))
        sys.exit(-1)

def LogWrite (Text, Log_MessType):
    line = datetime.datetime.strftime(datetime.datetime.now(), "%Y.%m.%d %H:%M:%S") + "\t" + Log_MessType + "\t" + Text

    if ( Log_Level > 0):
        if ( Log_Level == 1 and Log_MessType == MESSTYPE['err']):
            LogWriteToFile(line)
        
        if ( Log_Level == 2 and (Log_MessType == MESSTYPE['err'] or Log_MessType == MESSTYPE['warn'])):
            LogWriteToFile(line)

        if ( Log_Level == 3 and (Log_MessType == MESSTYPE['err'] or Log_MessType == MESSTYPE['warn'] or Log_MessType == MESSTYPE['inf'])):
            LogWriteToFile(line)
         
        if ( Log_Level == 4 ):
            LogWriteToFile(line)


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
    LogWrite("Load config: " + PathToConfig, MESSTYPE['inf'])
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
        LogWrite("Config not exists from path: " + PathToConfig, MESSTYPE['err'])

# Open input JSON Config file
def OpenConfigFile(PathToLog):
    if (os.path.exists(str(PathToLog))):
        LogWrite("Entered config file: " + str(PathToLog), MESSTYPE['inf'])
        ReadParametersFromConfig(PathToLog)
    else:
        LogWrite("Error working whith log file: " + PathToLog, MESSTYPE['err'])

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
         responseutf = (response.content.decode("UTF-8"))
         LogWrite("Response content from check IP site: " + responseutf, MESSTYPE['dbg'])
         j = json.loads(responseutf)
         ip_str = j.get("ip")
         LogWrite("IP address from external site: " + ip_str, MESSTYPE['inf'])
         return(ip_str)
     else:
        LogWrite("Error request from: " + response.url, MESSTYPE['err'])
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
            LogWrite("Successfull edit DNS record: " + PARAM_DICT['subdomain'] + "\tIP: " + ExternalIP, MESSTYPE['inf'])
            return j
    else:
        LogWrite("Error edit DNS record: " + PARAM_DICT, MESSTYPE['err'])
        LogWrite(response, MESSTYPE['err'])
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
            LogWrite("Successfully creating DNS record: " + PARAM_DICT['subdomain'] + ' whith IP address: ' + content, MESSTYPE['inf'])
            return j
    else:
        LogWrite(response, MESSTYPE['err'])
        return response


LogWrite("============== Init ==============", MESSTYPE['dbg'])

if (len(sys.argv[1:]) > 0):
    Config_File = (sys.argv[1:])
    OpenConfigFile(Config_File)
else:
    if(Config_File != None):
        OpenConfigFile(Config_File)
    else:
        if (CheckAllParams(ALL_PARAM_DICT) != True):
                LogWrite("One or any input parameters not setted: ", MESSTYPE['err'])
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
        LogWrite("Successfully compare of internal and external IP addresses: " + ExternalIP, MESSTYPE['inf'])
    else:
        # Set IP
        EditDNSRecord(ALL_PARAM_DICT, SubDomainInfo['SubDomainID'], ExternalIP)

LogWrite("=============== End ===============", MESSTYPE['dbg'])


