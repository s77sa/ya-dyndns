#!/bin/python3
import pycurl
import io
#import requests
import sys
import json
from urllib.parse import urlencode


PY3 = sys.version_info[0] > 2

#YandexOAuth = 'ef3ce4a2f6f94781bd9c163c2459544d'
YandexFqdnMainDomain = 's77sa.ru'
YandexFqdnSubDomain = 'big-nas.s77sa.ru'
YandexPddAdressList = 'https://pddimp.yandex.ru/api2/admin/dns/list'
YandexPddAdressEdit = 'https://pddimp.yandex.ru/api2/admin/dns/edit'
YandexPddToken = 'WQCC72J6TNLIJJNZ5PMA63Z6G7D3WYBXAH62ZBUY7NMFPWOSXTUA'

MyIP = '217.69.139.200'
YandexSubDomainIP = ''
YandexSubDomainID = ''

class ResponseCont:
    def __init__(self):
        self.contents = None
        # if PY3:
        #     self.contents = self.contents.encode('ascii')

    def body_callback(self, buf):
        self.contents = buf


# sys.stderr.write("Testing %s\n" % pycurl.version)

# Get external IP from external internet site
def Get_ExternalIP():
    IP = ''
    response = ResponseCont()
    c = pycurl.Curl()
    c.setopt(c.URL, 'http://api.ipify.org?format=json')
    c.setopt(c.WRITEFUNCTION, response.body_callback)
    #c.setopt(c.HTTPHEADER, ['Content-Type: application/json','Accept-Charset: UTF-8'])
    #c.setopt(c.POSTFIELDS, '@request.json')
    c.perform()
    c.close()
    IP = json.loads(response.contents.decode("UTF-8"))
    #print(1, MyIP)
    return IP.get("ip")

# Get All information from Yandex DNS Information
def Get_DnsList(Domain, PddToken):#, OAuth):
    response = ResponseCont()
    c = pycurl.Curl()
    c.setopt(c.URL, YandexPddAdressList + '?domain=' + Domain)
    c.setopt(c.WRITEFUNCTION, response.body_callback)
    #c.setopt(c.HTTPHEADER, ['PddToken: ' + PddToken,'Authorization: OAuth: ' + OAuth])
    c.setopt(c.HTTPHEADER, ['PddToken: ' + PddToken])
    #c.setopt(c.POSTFIELDS, '@request.json')
    #c.setopt(c.POSTFIELDS, '@request.json')
    c.perform()
    c.close()
    return(response.contents.decode("UTF-8"))
    #print(2, DnsIP)
    #return DnsIP


def Get_IPSubDomain(SubDomain):
    SubDomainIP = ''
    SubDomainID = ''
    YaJsonDump = json.loads(Get_DnsList(Domain=YandexFqdnMainDomain, PddToken=YandexPddToken))#,OAuth=YandexOAuth))
    #outdict = YaJsonDump.
    #print(SubDomain)
    # print()
    if (YaJsonDump.get("success")) == "ok":
        for i in YaJsonDump.get("records"):
            # print(i.get("fqdn"))
            if i.get("fqdn") == SubDomain:
                SubDomainIP = i.get("content")
                # print(i.get("record_id"))
                SubDomainID = i.get("record_id")
                # print(SubDomainID)
    return SubDomainIP, SubDomainID


# curl -H 'PddToken: 123456789ABCDEF0000000000000000000000000000000000000' 
# -d 'domain=domain.com&record_id=1&subdomain=www&ttl=14400&content=127.0.0.1' 
# 'https://pddimp.yandex.ru/api2/admin/dns/edit'

def Add_IPSubDomain(IPSubDomain, SubDomain, Domain, PddToken):
    print("IPSubDomain","SubDomain","Domain")
    postfields = urlencode({"domain":Domain})
    response = ResponseCont()
    c = pycurl.Curl()
    c.setopt(c.URL, YandexPddAdressEdit + '?domain=' + Domain)
    c.setopt(c.WRITEFUNCTION, response.body_callback)
    c.setopt(c.HTTPHEADER, ['PddToken: ' + PddToken])
    c.setopt(c.POSTFIELDS, postfields)
    c.perform()
    c.close()
    return(response.contents.decode("UTF-8"))
    # return true


print(Get_IPSubDomain(YandexFqdnSubDomain))
# print(Add_IPSubDomain(
# IPSubDomain="192.168.25.7",
# SubDomain=YandexFqdnSubDomain,
# Domain=YandexFqdnMainDomain,
# PddToken=YandexPddToken))
#print(Get_IPSubDomain(YandexFqdnSubDomain))
#MyIP = Get_MyIP()
#print(MyIP , Get_MyIP())
