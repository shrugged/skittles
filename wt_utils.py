from unipath import Path
import sys
import json
import os
import time
import random
import string
from urlparse import urlparse
import httplib, sys
import socket
import re
import  requests.exceptions

AQUATONE_ROOT = Path(os.getenv('AQUATONEPATH', "~/aquatone")).expand_user()

def check_url(url):
    try:
        url = urlparse(url)
        conn = httplib.HTTPConnection(url.netloc, timeout=1)   
        conn.request("HEAD", url.path)
        if conn.getresponse():
            return True
        else:
            return False
    except (socket.error, httplib.HTTPException, requests.exceptions), e:
        return False

# aquatone discover
def read_hosts(filename):
    if os.path.isfile(filename):
        with open(filename) as h:
            hosts = json.load(h).keys()
        return hosts
    else:
        print("error reading file: %s", filename)
        sys.exit(1)

#subfinder
def read_hosts2(filename):
    if os.path.isfile(filename):
        with open(filename) as h:
            hosts = json.load(h)
        if not hosts:
            sys.exit(0)
        return hosts
    else:
    	print("error reading file: %s", filename)
        sys.exit(1)

# massdns
def read_hosts3(filename):
    hosts = []
    if os.path.isfile(filename):
        with open(filename) as content:
            for line in content:
                hosts.append(line.split(". ")[0])

    return hosts

#host per line
def read_hosts4(filename):
    hosts = []
    if os.path.isfile(filename):
        with open(filename) as content:
            for line in content:
                hosts.append(line.strip())

    return hosts

# HOME IS CORP/DOMAIN
def go_home(domain):
    path_domain = Path(AQUATONE_ROOT, domain)
    if path_domain.isdir():
    	path_domain.chdir()
    else:
    	print("error %s is not a dir", domain)
    	sys.exit(1)

def setup_report_dir(app_name, random_dir=True):
    if random_dir:
        date_dir = time.strftime('%y-%m-%d')
        date_dir += "-"
        date_dir += ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6))
    else:
        date_dir = ""

    report_dir = Path(Path.cwd(), [app_name, date_dir])
    report_dir.mkdir(parents=True)
    
    return report_dir

def whitelist_hosts(hosts, whitelists):
    c = len(hosts)
    for whitelist in whitelists:
        regex = re.compile(whitelist)
        regex_hosts = filter(regex.search, hosts)

    print("Whitelisted %d host(s)", c - len(hosts))
    return regex_hosts

def blacklist_hosts(hosts, blacklist):
    regex = re.compile(blacklist)
    regex_hosts = filter(regex.search, hosts)
    return [word for word in hosts if not any(bad in word for bad in regex_hosts)]

def usage(errmsg):
    '''
    Error Messages
    '''
    print("Usage: python %s [Options] use -h for help" % sys.argv[0])
    print("Error: %s" % errmsg)
    sys.exit(1)