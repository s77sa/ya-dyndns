#!/home/seven/Projects/py-venv/bin/python3
# import pycurl
import io
import requests
# import sys
import json
import datetime
# from urllib.parse import urlencode

ExternalIPSite = "http://api.ipify.org?format=json"

# YandexFqdnMainDomain = "s77sa.ru"
# YandexFqdnSubDomain = "big-nas.s77sa.ru"
# SubDomainTtl = 1800
# YandexPddAdressList = "https://pddimp.yandex.ru/api2/admin/dns/list"
# YandexPddAdressEdit = "https://pddimp.yandex.ru/api2/admin/dns/edit"
# YandexPddToken = "WQCC72J6TNLIJJNZ5PMA63Z6G7D3WYBXAH62ZBUY7NMFPWOSXTUA"

Log = "/home/seven/Projects/ya-dyndns/dyn-test.log"


class YaDynDns():
    # def ReadJsonConfig(self, Config):
    #     if(exis
    #     file = open(Config, "r")
    #     j = json.load(file)
    #     file.close()
    #     # print(j)
    #     return j

    def __init__(self, PathToConfig):
        print("init")
        j = self.ReadJsonConfig(PathToConfig)
        self.YandexFqdnMainDomain = j.get("YandexFqdnMainDomain")
        self.YandexFqdnSubDomain = j.get("YandexFqdnSubDomain")
        self.SubDomainTtl = j.get("SubDomainTtl")
        self.YandexPddAdressList = j.get("YandexPddAdressList")
        self.YandexPddAdressEdit = j.get("YandexPddAdressEdit")
        self.YandexPddToken = j.get("YandexPddToken")
        



ya = YaDynDns("/home/seven/Projects/ya-dyndns/ya-dyndns.json")

def WriteLog (Text):
    file = open(Log, "a")
    line = datetime.datetime.strftime(datetime.datetime.now(), "%Y.%m.%d %H:%M:%S") + "\t" + Text
    print(line)
    file.write(line + "\n")
    file.close()
    return True

def GetExternalIP(url):
     response = requests.get(url)
     if(response.status_code == 200):
        #  print(response.content.decode("UTF-8"))
         j = json.loads(response.content.decode("UTF-8"))
         return(j.get("ip"))
     else:
        # print("Error request from: "+ response.url)
        return None

from requests.auth import AuthBase
class TokenAuth(AuthBase):
    def __init__(self, token):
        self.token = token
 
    def __call__(self, r):
        r.headers["PddToken"] = f"{self.token}" 
        return r

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

# curl -H 'PddToken: 123456789ABCDEF0000000000000000000000000000000000000' 
# -d 'domain=domain.com&record_id=1&subdomain=www&ttl=14400&content=127.0.0.1' 
# 'https://pddimp.yandex.ru/api2/admin/dns/edit'

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
        

# WriteLog("============== Init ==============")
# externalip = (GetExternalIP(ExternalIPSite))
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

WriteLog("=============== End ===============")
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