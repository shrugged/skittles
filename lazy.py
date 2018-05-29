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
import dns.resolver
import re
import os
from tempfile import mkstemp
import wfuzz
import re
from google.cloud import storage
from google.api_core import exceptions
from termcolor import colored
import os 

logging.basicConfig(level=logging.CRITICAL)

def get_alteration_words(wordlist):
        return wordlist.readlines()

# will write to the file if the check returns true
def write_domain(wp, full_url):
    wp.write(full_url+'\n')


# adds word-NUM and wordNUM to each subdomain at each unique position
def insert_number_suffix_subdomains(list_buckets, wp, separator, alternation_words):
    for line in list_buckets:
        current_sub = line.strip().split(separator)
        for word in range(0, 10):
            for index, value in enumerate(current_sub):
                #add word-NUM
                original_sub = current_sub[index]
                current_sub[index] = current_sub[index] + separator + str(word)
                # join the list to make into actual subdomain (aa.bb.cc)
                actual_sub = separator.join(current_sub)
                write_domain(wp, actual_sub)
                current_sub[index] = original_sub

                #add wordNUM
                original_sub = current_sub[index]
                current_sub[index] = current_sub[index] + str(word)
                # join the list to make into actual subdomain (aa.bb.cc)
                actual_sub = separator.join(current_sub)
                write_domain(wp, actual_sub)
                current_sub[index] = original_sub

# adds word- and -word to each subdomain at each unique position
def insert_dash_subdomains(list_buckets, wp, separator, alteration_words, prefix="", suffix=""):
    for line in list_buckets:
        for word in alteration_words:
            current_sub = line.strip().split(separator)
            for index, value in enumerate(current_sub):
                original_sub = current_sub[index]

                current_sub[index] = ""
                # building bucket name
                if prefix:
                    current_sub[index] += prefix + separator
                current_sub[index] += original_sub + separator 
                if suffix:
                    current_sub[index] += suffix + separator 

                current_sub[index] += word.strip()
                # join the list to make into actual subdomain (aa.bb.cc)
                actual_sub = separator.join(current_sub)
                if len(current_sub[0]) > 0 and actual_sub[:1] is not separator:
                    write_domain(wp, actual_sub)
                else:
                    print(actual_sub)

                # second dash alteration
                current_sub[index] = word.strip()
                if prefix:
                    current_sub[index] += separator + prefix 
                current_sub[index] += separator + original_sub 
                if suffix:
                    current_sub[index] += separator + suffix 

                # join the list to make into actual subd
                actual_sub = separator.join(current_sub)

                if actual_sub[-1:] is not separator:
                    write_domain( wp, actual_sub)

                current_sub[index] = original_sub


# adds prefix and suffix word to each subdomain
def join_words_subdomains(list_buckets, wp, separator, alteration_words):
    for line in list_buckets:
        current_sub = line.strip().split(separator)
        for word in alteration_words:
            for index, value in enumerate(current_sub):
                original_sub = current_sub[index]
                current_sub[index] = current_sub[index] + word.strip()
                # join the list to make into actual subdomain (aa.bb.cc)
                actual_sub = separator.join(current_sub)
                write_domain(wp, actual_sub)
                current_sub[index] = original_sub
                # second dash alteration
                current_sub[index] = word.strip() + current_sub[index]
                actual_sub = separator.join(current_sub)
                write_domain(wp, actual_sub)
                current_sub[index] = original_sub

def change_words_subdomains(list_buckets, wp, separator, alteration_words):
    for line in list_buckets:
        current_sub = line.strip().split(separator)
        for index, value in enumerate(current_sub):
            original_sub = current_sub[index] + '\n'
            if original_sub in alteration_words:
                for word in alteration_words:
                    if word is not original_sub:
                        current_sub[index] = word.strip()
                        actual_sub = separator.join(current_sub)
                        current_sub[index] = original_sub.strip()
                        write_domain(wp, actual_sub)

def fuzz_words_subdomains(list_buckets, wp, separator, alteration_words):
    for line in list_buckets:
        current_sub = line.strip().split(separator)
        for index, value in enumerate(current_sub):
            original_sub = current_sub[index]
            if "FUZZ" in original_sub:
                for word in alteration_words:
                    current_sub[index] = word.strip()
                    actual_sub = separator.join(current_sub)
                    current_sub[index] = original_sub.strip()
                    write_domain(wp, actual_sub)


def remove_duplicates(filename):
  with open(filename) as b:
    blines = set(b)
    with open(filename, 'w') as result:
      for line in blines:
        result.write(line)

def remove_existing_results(l1, l2):
    return [x for x in l1 if x not in l2]

def get_line_count(filename):
    with open(filename, "r") as lc:
        linecount = sum(1 for _ in lc)
    return linecount

def brute_force(input_file):
    results = []
    h = [("Host", "FUZZ")]
    with wfuzz.FuzzSession(scanmode=True,url="https://storage.googleapis.com",hc=[404], payloads=[("file",dict(fn=input_file))], headers=h) as sess:
        for r in sess.fuzz():
            if r.code == 403:
                print(colored(r.description, "red"))
                results.append(r.description)
            elif r.code == 200:
                print(colored(r.description, "blue"))
                results.append(r.description)
            elif r.code == 400:
                print(colored(r.description, "yellow"))
                results.append(r.description)

            if r.code != 400 and r.code != -1:
                try:
                    report_files_buckets(r.description)
                except Exception, e:
                    print("Error listing files: " + str(e))

    print("Took %d seconds.", int(sess.stats.totaltime))

    return results
def list_bucket(bucket_name):
    l = []
    """Lists all the blobs in the bucket."""
    storage_client = storage.Client()
    # lowercase because it doesn't work otherwise
    bucket = storage_client.get_bucket(bucket_name.lower())

    blobs = bucket.list_blobs()

    for blob in blobs:
        l.append(blob.name+"\n")

    return l

def report_files_buckets(name):
    path = os.path.expanduser('~/lazy')
    l = list_bucket(name)
    if l:
        with open(path + "/"+name, "w") as wp:
            wp.writelines(l)
    else:
        print("Number of files: %d", len(l))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input",
                        help="List of subdomains input", default='-',type=argparse.FileType('r'))
    parser.add_argument("-o", "--output",
                        help="Output location for altered subdomains",default='-',
                        type=argparse.FileType('w'))
    parser.add_argument("-w", "--wordlist",
                        help="List of words to alter the subdomains with",
                        required=False, default="/home/shrug/wordlist/words.txt",type=argparse.FileType('r'))
    parser.add_argument("-sf", "--suffix_file",
                        help="List of words to alter the subdomains with",
                        required=False, type=argparse.FileType('r'))
    parser.add_argument("-p", "--prefix",default="")
    parser.add_argument("-x", "--suffix",default="")
    parser.add_argument("-s", "--separator",default="-")
    parser.add_argument("-n", "--change-names",default=False,action='store_true')
    parser.add_argument("-j", "--join",default=False,action='store_true')
    parser.add_argument("-d", "--dash",default=False,action='store_true')
    parser.add_argument("-u", "--numbers",default=False,action='store_true')
    parser.add_argument("-f", "--fuzz",default=True,action='store_true')
    parser.add_argument("-r", "--rlevel",default=99,type=int)

    args = parser.parse_args()
    alteration_words = get_alteration_words(args.wordlist)
    bf = args.input
    results = []
    nb_run = 0

    print(os.environ['GOOGLE_APPLICATION_CREDENTIALS'])

    while True:
        _, output_tmp = mkstemp()
        print output_tmp

        #with open(output_tmp, "a+") as wp:
        wp = open(output_tmp, "a+")
        print(get_line_count(output_tmp))
        if args.dash:
            print "d"
            insert_dash_subdomains(bf, wp, args.separator, alteration_words)
            print(get_line_count(output_tmp))
        if args.join:
            print "j"
            join_words_subdomains(bf, wp, args.separator, alteration_words)
            print(get_line_count(output_tmp))
        if args.change_names and nb_run == 0:
            print "n"
            change_words_subdomains(bf, wp, args.separator, alteration_words)
            print(get_line_count(output_tmp))
        if args.numbers:
            print "u"
            insert_number_suffix_subdomains(bf, wp, args.separator, alteration_words)
            print(get_line_count(output_tmp))
        if args.fuzz and nb_run == 0:
            print "f"
            fuzz_words_subdomains(bf, wp, args.separator, alteration_words)
            print(get_line_count(output_tmp))

        #remove_duplicates(output_tmp)
        print("Got %s alternate names, brute forcing: ", get_line_count(output_tmp))
        try:
            bf = brute_force(output_tmp)
        except wfuzz.exception.FuzzExceptBadOptions:
            pass
        bf = remove_existing_results(bf, results)

        nb_run += 1

        if len(bf) > 0:
            results += bf

            if nb_run < args.rlevel:
                print("Running again with %d results: ", len(bf))
            else:
                break
        else:
           break

    print("Found %d results.",len(results))
    for l in results:
        args.output.write(l+"\n")

if __name__ == "__main__":
    main()

