#!/usr/bin/env python2


import requests
import os
import argparse
import json
import sys
from urlparse import urlparse
from wt_utils import *
import wfuzz
import requests.exceptions
import simplejson

URL = "http://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original,statuscode&collapse=urlkey"

parser = argparse.ArgumentParser(description='Bruteforce webservers')
parser.add_argument('--domain', required='True')
parser.add_argument('--bruteforce', action='store_true', default=True)
parser.add_argument('--archive', action='store_true', default=True)
parser.add_argument('--blacklist',action='append')
parser.add_argument('--whitelist',action='append')

args = parser.parse_args()

def write_host_results(report_dir, host, r):
	results = []

	# line 0 is descriptions
	for i in r[1:]:
		if "robots.txt" in i[0]:
			continue

		if "favicon.ico" in i[0]:
			continue

		if urlparse(i[0]).path == '/' or urlparse(i[0]).path == '':
			continue

		try:
			results.append(str(i[0]) + "\n")
		except UnicodeEncodeError:
			print ("Unicode Error")
			pass

	if len(results) > 0:
		f = Path(report_dir, host)
		with open(f.absolute() +".txt", "w") as wp:
			wp.writelines(results)
			#for r in results:
			#	tldextract.extract(r)

	return len(results)

def brute_force(filename):
	#h = [("Host", host)]
	found = 0
	with wfuzz.FuzzSession(scanmode=True,url="FUZZ",hc=[404,301,302,'XXX','-01'], payloads=[("file",dict(fn=str(filename)))], printer=(filename+".out", "csv")) as sess:
		for r in sess.fuzz():
			found += 1
			print r

	print("Took %d seconds, made %d requests.", int(sess.stats.totaltime), sess.stats.processed())
	return found

def get_wayback(report_dir, host):
	r = requests.get(URL % host)

	if "Blocked By Robots" in r.text:
		return 0

	try:
		if len(r.json()) > 0:
			h = write_host_results(report_dir, host, r.json())
			return h
		else:
			return 0
	except simplejson.scanner.JSONDecodeError:
		pass

def main():
	go_home(args.domain)
	report_dir = setup_report_dir("wayback", False)

	#hosts = read_hosts("hosts.json")
	#hosts = read_hosts2("subfinder.json")
	#hosts = read_hosts4("subfinder-18-05-23.txt")
	#hosts = read_hosts4("services.txt")
	hosts = read_hosts3("massdns-18-06-16.txt")

	if args.whitelist:
	    hosts = whitelist_hosts(hosts, whitelist)

	if args.blacklist:
	    c = len(hosts)
	    for blacklist in args.blacklist:
	        hosts = blacklist_hosts(hosts, blacklist)
	    print("Blacklisted %d host(s)", c - len(hosts))

	print("Getting the archive for all subdomain: %s", args.domain)

	if not hosts:
		sys.exit(0)

	for host in hosts:
		try:
			print("Requesting host: %s", host)

			input_file = Path(report_dir, host +".txt")

			if args.archive and input_file.exists():
				print("Using archive file: %s", input_file)
				#print("Print brute forcing %d results.", w)
				bf = brute_force(input_file)
			else:
				w = 0
				try:
					w = get_wayback(report_dir, host)
				except requests.exceptions.ConnectionError:
					pass
				print("Found %d results in wayback.", w)

				if w > 0 and args.bruteforce:
					print("Brute forcing %d results.", w)
					try:
						bf = brute_force(input_file)
					except (simplejson.scanner.JSONDecodeError, wfuzz.exception.FuzzExceptBadFile):
						pass

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

		except wfuzz.exception.FuzzExceptBadOptions:
			pass


		

if __name__ == "__main__":
    main()
