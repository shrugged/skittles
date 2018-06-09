#!/usr/bin/env python
# released at BSides Canberra by @infosec_au and @nnwakelam
# <3 silvio

import argparse
import threading
import time
import datetime
from threading import Lock
from Queue import Queue as Queue
from google.cloud import storage

import tldextract
from tldextract.tldextract import LOG
import logging
from termcolor import colored
import re
import os
from tempfile import mkstemp
import wfuzz
import re
from google.cloud import storage
from google.api_core import exceptions
from termcolor import colored
import os 
import itertools
from wt_utils import *
import requests

logging.basicConfig(level=logging.CRITICAL)

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--input",
                    help="List of subdomains input", default='-',type=argparse.FileType('r'))
parser.add_argument("-o", "--output",
                    help="Output location for altered subdomains",default='-',
                    type=argparse.FileType('w'))
parser.add_argument("-w", "--wordlist",
                    help="List of words to alter the subdomains with",
                    required=False, default="/home/shrug/wordlist/words.txt",type=argparse.FileType('r'))
parser.add_argument("-s", "--separator",default="-")
parser.add_argument("-r", "--rlevel",default=99,type=int)
parser.add_argument('--list-files', action='store_true', default=False)
parser.add_argument('--list-perms', action='store_true', default=True)

args = parser.parse_args()
alteration_words = get_alteration_words(args.wordlist)
#alteration_words = [str(x) for x in range(1,100)]

# will write to the file if the check returns true
def write_domain(wp, full_url):
    wp.write(full_url+'\n')

def generate_bag_of_words(n):
    if "FUZZ" in n:
        return alteration_words
    else:
        return [n]

def fuzz_words_subdomains(list_buckets, wp, separator):
    for line in list_buckets:
        current_sub = line.strip().split(separator)
        m = map(generate_bag_of_words, current_sub)
        for listAnswer in itertools.product(*m):
            #print separator.join(listAnswer)
            write_domain(wp, separator.join(listAnswer))

def remove_duplicates(filename):
  with open(filename) as b:
    blines = set(b)
    with open(filename, 'w') as result:
      for line in blines:
        result.write(line)

def get_line_count(filename):
    with open(filename, "r") as lc:
        linecount = sum(1 for _ in lc)
    return linecount

def brute_force(input_file):
    results = []
    h = [("Host", "FUZZ")]
    with wfuzz.FuzzSession(scanmode=True,method="HEAD",url="https://storage.googleapis.com",hc=[404], payloads=[("file",dict(fn=input_file))], headers=h) as sess:
        for r in sess.fuzz():
            if r.code == 403:
                print(colored(r.description, "red"))
                results.append(r.description)
            elif r.code == 200:
                print(colored(r.description, "blue"))
                results.append(r.description)
            elif r.code == 400:
                print(colored(r.description, "yellow"))
                #results.append(r.description)

            try:
                t = requests.get("https://www.googleapis.com/storage/v1/b/" + r.description)
                if t.status_code == 200:
                    print(t.text)
            except requests.exceptions:
                pass

            if args.list_perms and r.code != 404:
                try:
                    t = requests.get("https://content.googleapis.com/storage/v1/b/" + r.description + 
                    "/iam/testPermissions?permissions=storage.objects.get&permissions=storage.buckets.delete" + 
                    "&permissions=storage.buckets.getIamPolicy&permissions=storage.buckets.setIamPolicy&permissions=storage.buckets.update" + 
                    "&permissions=storage.objects.delete&permissions=storage.objects.getIamPolicy&permissions=storage.objects.create" +
                    "&permissions=storage.objects.list&permissions=storage.objects.setIamPolicy&permissions=storage.objects.update")
                    if t.status_code == 200:
                        perms = t.json().get("permissions")
                        if perms:
                            print("List of permissions: %s.", perms)
                except requests.exceptions:
                    pass


            if r.code != 400 and r.code != -1:
                t = requests.get("https://" + r.description + ".appspot.com")
                if not t.status_code == 404:
                    print("Get https://" + str(r.description) + ".appspot.com: %s",  t.status_code)

                if args.list_files:
                    try:
                        report_files_buckets(r.description)
                    except (TypeError, requests.exceptions, exceptions.Forbidden, exceptions.NotFound, exceptions.ServiceUnavailable, KeyboardInterrupt), e:
                        pass

    print("Took %d seconds.", int(sess.stats.totaltime))

    return results

def remove_existing_results(l1, l2):
    return [x for x in l1 if x not in l2]

def main():
    bf = args.input
    results = []
    nb_run = 0

    print("Using: " + os.environ['GOOGLE_APPLICATION_CREDENTIALS'])

    while True:
        _, output_tmp = mkstemp()
        print("Tempfile is: %s", output_tmp)

        with open(output_tmp, 'a+') as wp:
            fuzz_words_subdomains(bf, wp, args.separator)

            remove_duplicates(output_tmp)
            print("Got %s alternate names, brute forcing: ", get_line_count(output_tmp))
            try:
                bf = brute_force(output_tmp)
            except:
                pass
        
        bf = remove_existing_results(bf, results)

        nb_run += 1

        if len(bf) > 0:
            results += bf

            if nb_run < args.rlevel:
                print("Running again with %d results: ", len(bf))
                bf = [s + "-FUZZ" for s in bf]
            else:
                break
        else:
           break

    print("Found %d results.",len(results))
    for l in results:
        args.output.write(l+"\n")

if __name__ == "__main__":
    main()

