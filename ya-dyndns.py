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

################# Do not edis this variables #############
EXTERNALCHECKIPSITE = "http://api.ipify.org?format=json"
ALLPARAMDICT = {'url_list':'','url_edit':'', 'token':'', 'domain':'', 'subdomain':'', 'subdomainid':'', 'ip':'', 'ttl':''}
MESSTYPE = defaultdict(lambda: 'NULL', {'err':'ERROR','warn':'WARRNING','inf':'INFO', 'dbg': 'DEBUG'})
##########################################################

################# Editable variables #####################
logpath = "./dyn-test.log"
logtostdout = True # True or False
logmaxsize = 5242880 # Bytes 
loggzcount = 5 # Max GZ archived log files
loglevel = 4 # 0 - disable log, 1 - only error, 2 - error and warning, 3 - error, warning and info, 4 - all
configfile = "./ya-dyndns.json"
ALLPARAMDICT['domain'] = None # FQDN main domain
ALLPARAMDICT['subdomain'] = None # FQDN sub domain
ALLPARAMDICT['ttl'] = None # TTL for sub domain
ALLPARAMDICT['url_list'] = None # Yandex Pdd Url for list
ALLPARAMDICT['url_edit'] = None # Yandex Pdd Url for edit
ALLPARAMDICT['url_add'] = None # Yandex Pdd Url for add record
ALLPARAMDICT['token'] = None # Yandex Pdd Token

# ALLPARAMDICT['domain'] = "???????????" # FQDN main domain
# ALLPARAMDICT['subdomain'] = "??????????" # FQDN sub domain
# ALLPARAMDICT['ttl'] = 1800 # TTL for sub domain
# ALLPARAMDICT['url_list'] = "https://pddimp.yandex.ru/api2/admin/dns/list" # Yandex Pdd Url for list
# ALLPARAMDICT['url_edit'] = "https://pddimp.yandex.ru/api2/admin/dns/edit" # Yandex Pdd Url for edit
# ALLPARAMDICT['url_add'] = "https://pddimp.yandex.ru/api2/admin/dns/add" # Yandex Pdd Url for add record
# ALLPARAMDICT['token'] = "???????????????????????" # Yandex Pdd Token
##########################################################

# ############### API Help links #########################
# https://connect.yandex.ru/portal/services/webmaster/resources/
# https://yandex.ru/dev/connect/directory/api/about.html

def log_to_tar(pathtolog, gzcount):
    if(os.path.exists(pathtolog)):
        tar = tarfile.open(pathtolog+"."+str(gzcount + 1)+".gz", "w:gz")
        tar.add(pathtolog)
        tar.close()
        # Delete current log file
        os.remove(pathtolog)

def log_rotate(pathtolog):
    listfiles = {}
    gzcount = 0
    if(os.path.exists(pathtolog)):
        if (os.path.getsize(pathtolog) > logmaxsize):
            # Archive current log file
            log_to_tar(os.path.realpath(pathtolog), gzcount)
            dir_name = (os.listdir(os.path.dirname(pathtolog)))
            # Search all archived log files for delete old
            for filename in dir_name:
                if (filename.find("gz",0,len(filename))) > 0:
                    try:
                        listfiles.update({filename:datetime.datetime.fromtimestamp(os.path.getctime(filename))})
                        curr_count = int(filename.rpartition('log.')[2].partition('.gz')[0])
                        if curr_count > gzcount:
                            gzcount = curr_count
                        # print(file_name.rpartition('.gz')[0])
                    except Exception as e:
                        print("Error working whith log archives.\n" + str(e))

        sortedlistfiles = sorted(listfiles.items(), key=lambda x:x[1])
        sortedlistfiles.reverse()
        i_count = 0
        for item in sortedlistfiles:
            i_count += 1
            if(i_count >= loggzcount):
                # Delete old archive logs
                print("Delete old log file: " + os.path.realpath(item[0]))
                os.remove(os.path.realpath(item[0]))

# print(logpath)
# log_rotate(logpath)
# sys.exit(0)

def log_write_to_file(textline):
    if (logtostdout):
        print(textline)

    try:
        file = open(logpath, "a")
        file.write(textline + "\n")
        file.close()
        log_rotate(logpath) # Log rotate 
        return True
    except Exception as e:
        print("Error writing to log.\n" + str(e))
        sys.exit(-1)

def log_write (Text, Log_MessType):
    line = datetime.datetime.strftime(datetime.datetime.now(), "%Y.%m.%d %H:%M:%S") + "\t" + Log_MessType + "\t" + Text

    if ( loglevel > 0):
        if ( loglevel == 1 and Log_MessType == MESSTYPE['err']):
            log_write_to_file(line)
        
        if ( loglevel == 2 and (Log_MessType == MESSTYPE['err'] or Log_MessType == MESSTYPE['warn'])):
            log_write_to_file(line)

        if ( loglevel == 3 and (Log_MessType == MESSTYPE['err'] or Log_MessType == MESSTYPE['warn'] or Log_MessType == MESSTYPE['inf'])):
            log_write_to_file(line)
         
        if ( loglevel == 4 ):
            log_write_to_file(line)


class TokenAuth(AuthBase):
    def __init__(self, token):
        self.token = token
 
    def __call__(self, r):
        r.headers["PddToken"] = f"{self.token}" 
        return r
# Read JSON needded for read_parameters_from_config() 
def read_json_config(Config):
    if (os.path.exists(Config)):
        file = open(Config, "r")
        j = json.load(file)
        file.close()
        # print(j)
        return j
    else:
        return None

# Read parameters from config file
def read_parameters_from_config(pathtoconfig):
    log_write("Load config: " + pathtoconfig, MESSTYPE['inf'])
    if (os.path.exists(pathtoconfig)):
        j = read_json_config(pathtoconfig)
        ALLPARAMDICT['domain'] = j.get("YandexFqdnMainDomain") # FQDN main domain
        ALLPARAMDICT['subdomain'] = j.get("YandexFqdnSubDomain") # FQDN sub domain
        ALLPARAMDICT['ttl'] = j.get("SubDomainTtl") # TTL for sub domain
        ALLPARAMDICT['url_list'] = j.get("YandexPddAdressList") # Yandex Pdd Url for list
        ALLPARAMDICT['url_edit'] = j.get("YandexPddAdressEdit") # Yandex Pdd Url for edit
        ALLPARAMDICT['url_add'] = j.get("YandexPddAdressAdd") # Yandex Pdd Url for add record
        ALLPARAMDICT['token'] = j.get("YandexPddToken") # Yandex Pdd Token
    else:
        log_write("Config not exists from path: " + pathtoconfig, MESSTYPE['err'])

# Open input JSON Config file
def open_config_file(pathtolog):
    if (os.path.exists(str(pathtolog))):
        log_write("Entered config file: " + str(pathtolog), MESSTYPE['inf'])
        read_parameters_from_config(pathtolog)
    else:
        log_write("Error working whith log file: " + pathtolog, MESSTYPE['err'])

# Check input parameters
def check_all_params(paramdict):
    status = True
    for param in paramdict:
        if(paramdict[param] == None or paramdict[param] == ''):
            status = False
    return status

# Get IP from external WEB site
def get_external_ip(url):
    response = None
    ipstr = None
    try:
        response = requests.get(url)
    except (requests.ConnectionError) as connectexcept:
        log_write("Error request from site: " + url + ", or no internet connection.", MESSTYPE['err'])
        
    if (response != None):
        if(response.status_code == 200):
            responseutf = (response.content.decode("UTF-8"))
            log_write("Response content from check IP site: " + responseutf, MESSTYPE['dbg'])
            j = json.loads(responseutf)
            ipstr = j.get("ip")
            log_write("IP address from external site: " + ipstr, MESSTYPE['inf'])
            return(ipstr)
        else:
            log_write("Error request from: " + response.url, MESSTYPE['err'])
    return ipstr


# Get All information from Yandex DNS Information
def get_yandex_dns_list(urllist, domain, token):
    log_write("Input params. urllist=" + urllist + " domain=" + domain + " token=" + token, MESSTYPE['dbg'])
    response = requests.get(
        urllist,
        auth=TokenAuth(token),
        params={"domain": domain}
    )
    status = response.status_code
    log_write("Response from: " + urllist + " status: " + str(status), MESSTYPE['dbg'])
    if ( status == 200):
        j = json.loads(response.content.decode("UTF-8"))
        log_write("Json response:\n" + str(j), MESSTYPE['dbg'])
        if (j.get("success") == "ok"):
            return j
    else:
        return None     

# Get IP adn ID from all contents
def get_ip_sub_domain(jsoncontent, subdomain):
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


def edit_dns_record(paramdict, recordid, content):
    status = 0
    response = requests.post(
        paramdict['url_edit'],
        auth=TokenAuth(paramdict['token']),
        params={
            "domain": paramdict['domain'],
            "record_id": recordid,
            #"subdomain":subdomain,
            "content":content,
            "ttl":paramdict['ttl']}
    )
    if (response.status_code == 200):
        j = json.loads(response.content.decode("UTF-8"))
        if (j.get("success") == "ok"):
            log_write("Successfull edit DNS record: " + paramdict['subdomain'] + "\tIP: " + externalip, MESSTYPE['inf'])
            return j
    else:
        log_write("Error edit DNS record: " + paramdict, MESSTYPE['err'])
        log_write(response, MESSTYPE['err'])
        return response
        


def create_dns_record(paramdict, record_type, content):
    status = 0
    # print(paramdict['subdomain'].partition('.')[0])
    # print(check_all_params(paramdict))
    response = requests.post(
        paramdict['url_add'],
        auth=TokenAuth(paramdict['token']),
        params={
            "domain": paramdict['domain'],
            "type": record_type,
            "subdomain":paramdict['subdomain'].partition('.')[0],
            "content":content,
            "ttl":paramdict['ttl']}
    )
    if (response.status_code == 200):
        j = json.loads(response.content.decode("UTF-8"))
        if (j.get("success") == "ok"):
            log_write("Successfully creating DNS record: " + paramdict['subdomain'] + ' whith IP address: ' + content, MESSTYPE['inf'])
            return j
    else:
        log_write(response, MESSTYPE['err'])
        return response


log_write("============== Init ==============", MESSTYPE['dbg'])

if (len(sys.argv[1:]) > 0):
    configfile = (sys.argv[1:])
    open_config_file(configfile)
else:
    if(configfile != None):
        open_config_file(configfile)
    else:
        if (check_all_params(ALLPARAMDICT) != True):
                log_write("One or any input parameters not setted: ", MESSTYPE['err'])
                sys.exit(1)

externalip = get_external_ip(EXTERNALCHECKIPSITE)
if (externalip != None):
    externalcontent = (get_yandex_dns_list(ALLPARAMDICT['url_list'], ALLPARAMDICT['domain'], ALLPARAMDICT['token']))
    
    subdomaininfo = (get_ip_sub_domain(externalcontent, ALLPARAMDICT['subdomain']))
    if(subdomaininfo['subdomainid'] == None):
        # print(ALLPARAMDICT)
        # Create Sub Domain
        create_dns_record(ALLPARAMDICT, 'A', externalip)
        # print("if create")
        # print(subdomaininfo['SubDomainID'])
        # print(subdomaininfo['SubDomainID'])
    else:
            # Compare IP
        if (subdomaininfo['SubDomainIP'] == externalip):
            log_write("Successfully compare of internal and external IP addresses: " + externalip, MESSTYPE['inf'])
        else:
            # Set IP
            edit_dns_record(ALLPARAMDICT, subdomaininfo['subdomainid'], externalip)
    

log_write("=============== End ===============", MESSTYPE['dbg'])


