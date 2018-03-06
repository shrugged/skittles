#!/usr/bin/env python2

import json
import wfuzz
import argparse
from unipath import Path
import sys
import os
import string
from random import *
import re
import time
import signal

AQUATONE_ROOT = Path(os.getenv('AQUATONEPATH', "~/aquatone")).expand_user()
ALL_CHARS = string.ascii_letters + string.digits

parser = argparse.ArgumentParser(description='Bruteforce webservers')
parser.add_argument('--domain', required='True')
parser.add_argument('--append',  action='store_true',default=True)
parser.add_argument('--output', default="dirsearch.json")
parser.add_argument('--verbose',action='store_true')
parser.add_argument('--blacklist',action='append')
parser.add_argument('--whitelist',action='append')
parser.add_argument('--aggressive')

options, w = parser.parse_known_args()
output = options.output
results = {}

def whitelist_hosts(hosts, whitelist):
    regex = re.compile(whitelist)
    regex_hosts = filter(regex.search, hosts)
    return regex_hosts

def blacklist_hosts(hosts, blacklist):
    regex = re.compile(blacklist)
    regex_hosts = filter(regex.search, hosts)
    return [word for word in hosts if not any(bad in word for bad in regex_hosts)]

# return host with urls
# -1 if failed to connect
def scan_host(schema, u):
    host = {}
    baseline = {}
    random_string = "".join(choice(ALL_CHARS) for x in range(randint(24, 24)))
    payload = "/FUZZ{"+random_string+"}"
    sess = wfuzz.get_session(' '.join(w))
    
    sess.hh=['BBB']
    for res in sess.fuzz(scanmode=True,url=schema+u+payload):
        if res.is_baseline:
            baseline = res
            print(vars(res))
        else:
            p = process_url(res)
            if p > 0:
                if not res.words == baseline.words and \
                   not res.chars == baseline.chars and \
                   not res.lines == baseline.lines or \
                   res.md5 != baseline.md5:
                    host[res.description] = p
            elif p == 0:
                continue
            else:
                if options.verbose:
                    print("Error connecting to host.", u)
                    #host['*error*'] = {"code": -1, "error": res.description}
                    return -1

                sess.close()
                break

    print("Took %d seconds, made %d requests.", int(sess.stats.totaltime), sess.stats.processed())
    return host

# return processed url
# 0 if baseline
# -1 if error
def process_url(res):
    if res.is_baseline:
        if res.code == -1:
            return -1
        else:
            return 0

    res_entry = {
        "chars": res.chars,
        "code": res.code,
        "lines": res.lines,
        "words": res.words,
        "nres": res.nres,
        "md5": res.md5,
        "method": res.history._request.method,
        "schema": res.history._request.schema
    }

    if res.plugins_res:
        if not res.plugins_res[0].source == 'Recursion':
            res_entry['plugins'] = vars(res.plugins_res[0])

    #if options.debug:
    #    res_entry['debug'] = res.history.raw_content
    
    if 'Server' in res.history.headers.response:
        res_entry['server'] = res.history.headers.response['Server']
    if 'Location' in res.history.headers.response:
        res_entry['location'] = res.history.headers.response['Location']

    if options.verbose:
        print(str(res.payload) + " " + str(res_entry))

    return res_entry

def list_hosts():
    with open("hosts.json") as h:
        hosts = json.load(h).keys()
    return hosts

def save_results():
    with open(output, 'w') as outfile:
        json.dump(results, outfile)

def change_home():
    path_domain = Path(AQUATONE_ROOT, options.domain)
    path_domain.chdir()

def read_previous_results():
    with open(output, 'r') as infile:
            results = json.load(infile)
            print("Starting with %d result(s)", len(results))

def main():
    try:
        change_home()
        hosts = list_hosts()
        print("Using Aquatone Path : %s", AQUATONE_ROOT)
        print("Brute forcing for domain: %s", options.domain)
        print("Number(s) of url: %d",len(hosts))

        if options.append and Path(output).isfile():
            read_previous_results()
        
        options.time = time.time()
        results['options'] = vars(options)

        if options.whitelist:
            c = len(hosts)
            for whitelist in options.whitelist:
                hosts = whitelist_hosts(hosts, whitelist)
            print("Whitelisted %d host(s)", c - len(hosts))

        if options.blacklist:
            c = len(hosts)
            for blacklist in options.blacklist:
                hosts = blacklist_hosts(hosts, blacklist)
            print("Blacklisted %d host(s)", c - len(hosts))

        count = 0
        while count < len(hosts):
            host = hosts[count]
            print("Starting url: %s", host)

            #try https first
            scan = scan_host("https://", host)
            if scan == -1:
                scan = scan_host("http://", host)

            if scan > 0:
                results[host] = scan
                print("Number of results: %d", len(results[host]))
            count = count +1

        save_results()
    except KeyboardInterrupt:
        print("W: interrupt received, stopping")
    finally:
        save_results()

if __name__ == "__main__":
    main()
    