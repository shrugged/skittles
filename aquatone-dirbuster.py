#!/usr/bin/env python

import json
import wfuzz
import argparse
from unipath import Path
#from wfuzz.fuzzobjects import FuzzResult
import sys
import os

AQUATONE_ROOT = Path(os.getenv('AQUATONEPATH', "~/aquatone")).expand_user()
print("Using Aquatone Path : %s", AQUATONE_ROOT)

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

options = parser.parse_args()
results = {}
payload = "/FUZZ{gfdzswqer}"

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


def scan_url(sess, u):
    host = {}
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
                #host = {"error": -1}
                host[res.description] = res_entry
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

with open("hosts.json") as h:
    hosts = json.load(h).keys()
    print("Brute forcing for domain: %s", options.domain)
    print("Wordlist is: %s", options.wordlist)
    print("Number of url: %d",len(hosts))
    count = 0
    while count < len(hosts):
        host = hosts[count]
        print("Starting url: %s", host)
        fs = wfuzz.FuzzSession(hc=['404','429','503'],hh=['BBB'],payloads=[("file",dict(fn=str(wordlist)))], scanmode=True,rleve=2,script='robots')
        results[host] = scan_url(fs, "http://"+host+payload)
        print("Number of results: %d", len(results[host]))
        count = count +1

with open(output, 'w') as outfile:
        json.dump(results, outfile)
