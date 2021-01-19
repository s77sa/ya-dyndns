#!/home/seven/Projects/py-venv/bin/python3
# import pycurl
import io
import os
import requests
import sys
import json
import datetime
from requests.auth import AuthBase
from collections import defaultdict
# from urllib.parse import urlencode


################# Do not edis this variables #############
EXTERNAL_CHECKIP_SITE = "http://api.ipify.org?format=json"
ALL_PARAM_DICT = {'url_list':'','url_edit':'', 'token':'', 'domain':'', 'subdomain':'', 'subdomainid':'', 'ip':'', 'ttl':''}
# LOG_MESSTYPE_ERR = "ERROR"
# LOG_MESSTYPE_WARN = "WARRNING"
# LOG_MESSTYPE_INFO = "INFO"
MESSTYPE = defaultdict(lambda: 'NULL', {'err':'ERROR','warn':'WARRNING','inf':'INFO'})
##########################################################

################# Editable variables #####################
Log_Path = "/home/seven/Projects/ya-dyndns/dyn-test.log"
#Config_File = None
Config_File = "/home/seven/Projects/ya-dyndns/ya-dyndns.json"
ALL_PARAM_DICT['domain'] = None # FQDN main domain
ALL_PARAM_DICT['subdomain'] = None # FQDN sub domain
ALL_PARAM_DICT['ttl'] = None # TTL for sub domain
ALL_PARAM_DICT['url_list'] = None # Yandex Pdd Url for list
ALL_PARAM_DICT['url_edit'] = None # Yandex Pdd Url for edit
ALL_PARAM_DICT['token'] = None # Yandex Pdd Token

# ALL_PARAM_DICT['domain'] = "s77sa.ru" # FQDN main domain
# ALL_PARAM_DICT['subdomain'] = "big-nas.s77sa.ru" # FQDN sub domain
# ALL_PARAM_DICT['ttl'] = 1800 # TTL for sub domain
# ALL_PARAM_DICT['url_list'] = "https://pddimp.yandex.ru/api2/admin/dns/list" # Yandex Pdd Url for list
# ALL_PARAM_DICT['url_edit'] = "https://pddimp.yandex.ru/api2/admin/dns/edit" # Yandex Pdd Url for edit
# ALL_PARAM_DICT['token'] = "WQCC72J6TNLIJJNZ5PMA63Z6G7D3WYBXAH62ZBUY7NMFPWOSXTUA" # Yandex Pdd Token
##########################################################

# https://connect.yandex.ru/portal/services/webmaster/resources/
# https://yandex.ru/dev/connect/directory/api/about.html

# curl -H 'PddToken: 123456789ABCDEF0000000000000000000000000000000000000' 
# -d 'domain=domain.com&record_id=1&subdomain=www&ttl=14400&content=127.0.0.1' 
# 'https://pddimp.yandex.ru/api2/admin/dns/edit'


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

def ReadJsonConfig(Config):
    if (os.path.exists(Config)):
        file = open(Config, "r")
        j = json.load(file)
        file.close()
        # print(j)
        return j
    else:
        return None

def ReadParametersFromConfig(PathToConfig):
    WriteLog("Load config: " + PathToConfig, MESSTYPE['inf'])
    if (os.path.exists(PathToConfig)):
        j = ReadJsonConfig(PathToConfig)
        ALL_PARAM_DICT['domain'] = j.get("YandexFqdnMainDomain") # FQDN main domain
        ALL_PARAM_DICT['subdomain'] = j.get("YandexFqdnSubDomain") # FQDN sub domain
        ALL_PARAM_DICT['ttl'] = j.get("SubDomainTtl") # TTL for sub domain
        ALL_PARAM_DICT['url_list'] = j.get("YandexPddAdressList") # Yandex Pdd Url for list
        ALL_PARAM_DICT['url_edit'] = j.get("YandexPddAdressEdit") # Yandex Pdd Url for edit
        ALL_PARAM_DICT['token'] = j.get("YandexPddToken") # Yandex Pdd Token
    else:
        WriteLog("Config not exists from path: " + PathToConfig, MESSTYPE['err'])

def OpenConfigFile(PathToLog):
    if (os.path.exists(str(PathToLog))):
        WriteLog("Entered log file: " + str(PathToLog), MESSTYPE['inf'])
        ReadParametersFromConfig(PathToLog)
    else:
        WriteLog("Error working whith log file: " + PathToLog)

WriteLog("============== Init ==============", MESSTYPE['inf'])

if (len(sys.argv[1:]) > 0):
    Config_File = (sys.argv[1:])
    OpenConfigFile(Config_File)
else:
    if(Config_File != None):
        OpenConfigFile(Config_File)
    else:
        # if (YandexFqdnMainDomain == None or
        #     YandexFqdnSubDomain == None or
        #     SubDomainTtl == None or
        #     YandexPddAdressList == None or
        #     YandexPddAdressEdit == None or
        #     YandexPddToken== None):
        if (None in (ALL_PARAM_DICT['domain'], ALL_PARAM_DICT['subdomain'],  ALL_PARAM_DICT['ttl'], ALL_PARAM_DICT['url_list'], ALL_PARAM_DICT['url_edit'], ALL_PARAM_DICT['token'])):
                WriteLog("One or any input paramters not setted", MESSTYPE['err'])
                sys.exit(1)





# class YaDynDns():
#     def ReadJsonConfig(self, Config):
#         if (os.path.exists(Config)):
#             file = open(Config, "r")
#             j = json.load(file)
#             file.close()
#             # print(j)
#             return j
#         else:
#             return None

#     def __init__(self, PathToConfig):
#         print("Init class YaDynDns")
#         print(PathToConfig)
#         if (os.path.exists(PathToConfig)):
#             j = self.ReadJsonConfig(PathToConfig)
#             self.YandexFqdnMainDomain = j.get("YandexFqdnMainDomain")
#             self.YandexFqdnSubDomain = j.get("YandexFqdnSubDomain")
#             self.SubDomainTtl = j.get("SubDomainTtl")
#             self.YandexPddAdressList = j.get("YandexPddAdressList")
#             self.YandexPddAdressEdit = j.get("YandexPddAdressEdit")
#             self.YandexPddToken = j.get("YandexPddToken")
#         else:
#             WriteLog("Config not exists from path: " + PathToConfig, LOG_MESSTYPE_ERR)
        
        





# ya = YaDynDns("/home/seven/Projects/ya-dyndns/ya-dyndns.json")



def GetExternalIP(url):
     response = requests.get(url)
     if(response.status_code == 200):
        #  print(response.content.decode("UTF-8"))
         j = json.loads(response.content.decode("UTF-8"))
         ip_str = j.get("ip")
         WriteLog("IP from external site: " + ip_str)
         return(ip_str)
     else:
        WriteLog("Error request from: "+ response.url, MESSTYPE['err'])
        return None



# Get All information from Yandex DNS Information
def GetYandexDnsList(url, domain, token):
    response = requests.get(
        url,
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
    if (jsoncontent != None):
        for line in jsoncontent.get("records"):
            if (line.get("fqdn") == subdomain):
                subip = line.get("content")
                subid = line.get("record_id")
                # print(subip, subid)
        return {"SubDomainIP":subip, "SubDomainID":subid}
    else:
        return None



def AddIPToSubDomain(url, token, domain, subdomain, subdomainid, ip, ttl):
    status = 0
    response = requests.post(
        url,
        auth=TokenAuth(token),
        params={
            "domain": domain,
            "record_id": subdomainid,
            #"subdomain":subdomain,
            "content":ip,
            "ttl":ttl}
    )
    if (response.status_code == 200):
        j = json.loads(response.content.decode("UTF-8"))
        if (j.get("success") == "ok"):
            return j
    else:
        return response
        


def AddDNSRecord(url, token, domain, subdomain, subdomainid, ip, ttl):
    status = 0
    print 
    # response = requests.post(
    #     url,
    #     auth=TokenAuth(token),
    #     params={
    #         "domain": domain,
    #         "record_id": subdomainid,
    #         #"subdomain":subdomain,
    #         "content":ip,
    #         "ttl":ttl}
    # )
    # if (response.status_code == 200):
    #     j = json.loads(response.content.decode("UTF-8"))
    #     if (j.get("success") == "ok"):
    #         return j
    # else:
    #     return response



# externalip = (GetExternalIP(EXTERNAL_CHECKIP_SITE))
# if (externalip != None):
#     WriteLog("External IP = " + externalip)
#     subdomaininfo = GetIPSubDomain(GetYandexDnsList(
#         url=YandexPddAdressList,
#         domain=YandexFqdnMainDomain,
#         token=YandexPddToken
#     ), YandexFqdnSubDomain)
#     subdomainip = subdomaininfo.get("SubDomainIP")
#     subdomainid = subdomaininfo.get("SubDomainID")
#     WriteLog("Sub Domain IP = " + subdomainip)
#     if (subdomainip != None):
#         if (subdomainip != externalip):
#             print(AddIPToSubDomain(
#                 YandexPddAdressEdit,
#                 YandexPddToken,
#                 YandexFqdnMainDomain,
#                 YandexFqdnSubDomain,
#                 ipinfo.get("SubDomainID"),
#                 "192.168.4.8",
#                 SubDomainTtl
#                 )
#             )
#         else:
#             WriteLog("External IP equal SubDomain IP")
#     else:
#         WriteLog("Error reading Sub Domain IP")
# else:
#     WriteLog("Error getting external IP")

WriteLog("=============== End ===============", MESSTYPE['inf'])
# o = GetYandexDnsList(YandexPddAdressList, YandexFqdnMainDomain, YandexPddToken)
# #print(o)
# if (o != None):
#     ipinfo = GetIPSubDomain(o, YandexFqdnSubDomain)
#     print(ipinfo)

# print(AddIPToSubDomain(
#     YandexPddAdressEdit,
#     YandexPddToken,
#     YandexFqdnMainDomain,
#     YandexFqdnSubDomain,
#     ipinfo.get("SubDomainID"),
#     "192.168.4.8",
#     SubDomainTtl)
#     )