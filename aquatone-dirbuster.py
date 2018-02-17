#!/usr/bin/env python

import json
import wfuzz
import argparse
from unipath import Path
from wfuzz.fuzzobjects import FuzzResult

AQUATONE_ROOT = Path("~/aquatone").expand_user()

parser = argparse.ArgumentParser(description='Bruteforce webservers')
parser.add_argument('-d','--domain', required='True')
parser.add_argument('-w','--wordlist', required='True')

options = parser.parse_args()

path_domain = Path(AQUATONE_ROOT, options.domain)
path_domain.chdir()

results = {}

with open("hosts.json") as h:
    hosts = json.load(h).keys()
    print("Brute forcing for domain: %s", options.domain)
    print("Wordlist is: %s", options.wordlist)
    print("Number of url: %d",len(hosts))
    for host in hosts:

        results[host] = {}
        sess = wfuzz.FuzzSession(hc=['404'],hh=['BBB'],payloads=[("file",dict(fn=options.wordlist))], scanmode=True, follow=True)
        print("Starting url: %s", host)

        for res in sess.fuzz(url=host+"/FUZZ{gfdzswqer}"):
            print(vars(res))
            res_entry = {
                "chars": res.chars,
                "code": res.code,
                "payload": res.description,
                "lines": res.lines,
                "method": res.history.method,
                "server": server,
                "words": res.words,
                "md5": res.md5
            }
            results[host][res.url] = res_entry
            
        print("Number of results: %d", len(results[host]))


with open('dirsearch.json', 'w') as outfile:
        json.dump(results, outfile)
