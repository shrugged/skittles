#!/usr/bin/env python2

import json
import wfuzz
import argparse
from unipath import Path
#from wfuzz.fuzzobjects import FuzzResult
import sys
import os
import string
from random import *
import re

AQUATONE_ROOT = Path(os.getenv('AQUATONEPATH', "~/aquatone")).expand_user()
ALL_CHARS = string.ascii_letters + string.digits

parser = argparse.ArgumentParser(description='Bruteforce webservers')
parser.add_argument('-d','--domain', required='True')
parser.add_argument('-w','--wordlist', required='True')
parser.add_argument('-a','--append',  action='store_true')
parser.add_argument('-o', '--output')
parser.add_argument('-r', '--robots')
parser.add_argument('--debug',action='store_true')
parser.add_argument('-v', '--verbose',action='store_true')
parser.add_argument('--blacklist')
parser.add_argument('--whitelist')
parser.add_argument('--hc')
parser.add_argument('--rlevel')
parser.add_argument('-x', '--method')

options = parser.parse_args()

def whitelist_hosts(hosts, whitelist):
    regex = re.compile(whitelist)
    regex_hosts = filter(regex.search, hosts)
    return regex_hosts

def blacklist_hosts(hosts, blacklist):
    regex = re.compile(blacklist)
    regex_hosts = filter(regex.search, hosts)
    return [word for word in hosts if not any(bad in word for bad in regex_hosts)]

def scan_url(u, wordlist):
    host = {}
    h = "".join(choice(ALL_CHARS) for x in range(randint(15, 15)))
    sess = wfuzz.FuzzSession(headers=[('Test',h)],hc=['404','429','503'],hh=['BBB'],payloads=[("file",dict(fn=str(wordlist)))], scanmode=True,rleve=2)
    
    if options.hc:
        sess.data['hc']=options.hc.split(",")

    if options.rlevel:
        sess.data['rleve'] = options.rlevel

    if options.robots:
        sess.data['script'] = 'robots'

    if options.method:
        sess.data['method'] = options.method

    for res in sess.fuzz(url=u):
            res_entry = {
                "chars": res.chars,
                "code": res.code,
                "lines": res.lines,

                "words": res.words,
                "nres": res.nres,
                "md5": res.md5
            }

            if options.debug:
                res_entry['raw_content'] = res.history.raw_content
            if res.is_baseline and res.code == -1:
                host['*error*'] = {"code": -1, "error": res.description}
                break
            if 'Server' in res.history.headers.response:
                res_entry['server'] = res.history.headers.response['Server']
            if 'Location' in res.history.headers.response:
                res_entry['location'] = res.history.headers.response['Location']
            if res_entry and not res.is_baseline:
                host[res.description] = res_entry

    if options.verbose:
        print(host) 
    return host

def main():
    print("Using Aquatone Path : %s", AQUATONE_ROOT)
    results = {}
    random_string = "".join(choice(ALL_CHARS) for x in range(randint(15, 15)))
    payload = "/FUZZ{."+random_string+"}"
    print(payload)
    output = 'dirsearch.json'
    if options.output:
        output = options.output

    if options.robots:
        output = 'robots.json'

    wordlist = Path(Path.cwd(), options.wordlist)
    if not wordlist.isfile():
        print("No wordlist at, %s", str(wordlist))
        sys.exit(-1)

    path_domain = Path(AQUATONE_ROOT, options.domain)
    path_domain.chdir()

    if options.append and Path(output).isfile():
        with open(output, 'r') as infile:
            results = json.load(infile)
            print("Starting with %d result(s)", len(results))

    with open("hosts.json") as h:
        hosts = json.load(h).keys()
        print("Brute forcing for domain: %s", options.domain)
        print("Wordlist is: %s", options.wordlist)
        print("Number of url: %d",len(hosts))

        if options.whitelist:
            hosts = whitelist_hosts(hosts, options.whitelist)
            print("Whitelisted %d host(s)", len(hosts))

        if options.blacklist:
            c = len(hosts)
            hosts = blacklist_hosts(hosts, options.blacklist)
            print("Blacklisted %d host(s)", c - len(hosts))

        print(hosts)
        count = 0
        while count < len(hosts):
            host = hosts[count]
            print("Starting url: %s", host)

            results[host] = scan_url("http://"+host+payload, wordlist)
            print("Number of results: %d", len(results[host]))
            count = count +1

    with open(output, 'w') as outfile:
            json.dump(results, outfile)

if __name__ == "__main__":
    main()