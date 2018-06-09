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
from fuzzywuzzy import fuzz
import random
from urlparse import urlparse
import httplib, sys

from wt_utils import *

ALL_CHARS = string.ascii_letters + string.digits

parser = argparse.ArgumentParser(description='Bruteforce webservers')
parser.add_argument('--domain', required='True')
parser.add_argument('--verbose',action='store_true')
parser.add_argument('--blacklist',action='append')
parser.add_argument('--whitelist',action='append')
parser.add_argument('--waf',action='store_true', default=True)
parser.add_argument('--fuzzy',default=100)

options, w = parser.parse_known_args()

BLACKLIST_MD5 = ['19808e464563a3f91bfcbb24abd3da14',
                'c6b760e6b0be68f648b223590f8ceb8e',
                '0b1770cfb0a0eeb991cf9877c750add4',
                'ea1b9d80fc5181466257cd31016b8f12',
                '10c03357095165d318ac8031a47c49f3',
                '444bcb3a3fcf8389296c49467f27e1d6']

def scan_host(report_dir, schema, host):
    baseline = {}
    prev = {}
    found = 0

    # using a random string for baseline
    random_string = "".join(choice(ALL_CHARS) for x in range(randint(24, 24)))
    payload = "/FUZZ{"+random_string+"}"

    sess = wfuzz.get_session(' '.join(w))
    sess.hh=['BBB']
    if options.waf:
        sess.headers = [('X-Originating-IP', '127.0.0.1'),
                    ('X-Forwarded-For', '127.0.0.1'),
                    ('X-Remote-IP', '127.0.0.1'),
                    ('X-Remote-Addr', '127.0.0.1'),
                    ('Accept', '*/*'),
                    ('Authorization','Bearer ya29.c.ElnHBUhrOQqPxqadH8AFTZrvWChtMUmNfd-Hmmdoblnl7OO5SXId7D2TQVCajLsTyqfrUr1FxJpFLETEORnkEMZgGQ-_dwoA6j7q2VuzGFzr-YsKBW1KzJg5JQ'),
                    ('Content-Type',  'application/json')]

    url = schema+host+payload
    for res in sess.fuzz(scanmode=True,url=url):
        if res.code == -1:
            if res.is_baseline:
                sess.close()
                return False
            else:
                error = res.description
                #res.description = "*error*"
                if options.verbose:
                    print("*error*" +res.description)
                continue
        else:
            if res.is_baseline:
                baseline = res
                prev = res
                res.description = "*baseline*"

        if filter_url(baseline, prev, res):
            if options.verbose:
                print(str(vars(res)))

            if res.md5:
                #host[res.description] = process_url(res)
                #process_url(res)
                write_raw_content(report_dir, host, res.md5, res.history.raw_content)
                found += 1

            prev = res

    sess.close()

    print("Took %d seconds, found %s results, made %d requests.", int(sess.stats.totaltime), found, sess.stats.processed())
    return True

def write_raw_content(report_dir, host, filename, content):
    f = Path(report_dir, [host, filename])
    f.parent.mkdir(parents=True)
    f.write_file(content, mode="w")

def filter_url(baseline, prev, res):
    if res.history and baseline.history:
        fuzzy_bbb = fuzz.ratio(res.history.raw_content, baseline.history.raw_content)
        fuzzy_prev = fuzz.ratio(res.history.raw_content, prev.history.raw_content)
    else:
        return True

    if res.is_baseline:
        return False
    elif (res.words == baseline.words and \
           res.chars == baseline.chars and \
           res.lines == baseline.lines):
            return False
    elif res.md5 == baseline.md5:
        return False
    elif res.md5 in BLACKLIST_MD5:
        return False
    elif res.md5 == prev.md5:
        return False
    elif (res.words == prev.words and \
       res.chars == prev.chars and \
       res.lines == prev.lines):
        return False
    elif fuzzy_bbb > options.fuzzy:
        return False
    elif fuzzy_prev > options.fuzzy:
        return False
    # Don't bruteforce cloud storage
    elif res.history.headers.response.get("Server") == "UploadServer":
        return False
    elif res.history.headers.response.get("Server") == "AmazonS3":
        return False
    
    return True

def process_url(res):
    res_entry = {
        "payload": res.description,
        "chars": res.chars,
        "code": res.code,
        "lines": res.lines,
        "words": res.words,
        "nres": res.nres,
       # "md5": res.md5,
        "method": res.history._request.method,
        "schema": res.history._request.schema
    }

    if res.plugins_res:
        if not res.plugins_res[0].source == 'Recursion':
            res_entry['plugins'] = vars(res.plugins_res[0])

    if options.debug:
        res_entry['debug'] = res.history.raw_content
    
    if 'Server' in res.history.headers.response:
        res_entry['server'] = res.history.headers.response['Server']
    if 'Location' in res.history.headers.response:
        res_entry['location'] = res.history.headers.response['Location']

    return res_entry

def save_results_json(report_dir):
    with open(output, 'w') as outfile:
        json.dump(results, outfile)

def main():
    go_home(options.domain)
    report_dir = setup_report_dir("dirbuster")

    #hosts = read_hosts("hosts.json")
    #hosts = read_hosts2("subfinder.json")
    #hosts = read_hosts3("massdns-18-06-03.txt")
    hosts = read_hosts4("sublist3r.txt")

    print("Brute forcing for domain: %s", options.domain)
    print("Number(s) of url: %d",len(hosts))
    
    options.time = time.time()
    #results['options'] = vars(options)

    if options.whitelist:
        hosts = whitelist_hosts(hosts, whitelist)

    if options.blacklist:
        c = len(hosts)
        for blacklist in options.blacklist:
            hosts = blacklist_hosts(hosts, blacklist)
        print("Blacklisted %d host(s)", c - len(hosts))

    for host in hosts:
        try:
            print("Scanning host: %s", host)

            # test http vs https
            if check_url("https://" + host):
                scan_host(report_dir, "https://", host)
            else:
                if check_url("http://" + host):
                    scan_host(report_dir, "http://", host)
                else:
                    print("Error connecting to host : %s", host)
                    continue

            

        except KeyboardInterrupt:
            print("CTRL+C detected.")
            print("Options: [e]xit, [c]ontinue, [s]kip target.")
            option = raw_input()
            if option.lower() == 'e':
                sys.exit()
            if option.lower() == 'c':
                print("Starting over.")
            elif option.lower() == 's':
                print("Skipped host %s: ", host)

    print("Report Path: %s", report_dir.absolute())

if __name__ == "__main__":
    main()
    
