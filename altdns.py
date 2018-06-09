import altdns
import argparse
from unipath import Path
import os
import json
from altdns import altdns
from subprocess import Popen, PIPE, STDOUT
import string 
from random import *
import tldextract
from tempfile import mkstemp
import itertools

from wt_utils import *

AQUATONE_ROOT = Path(os.getenv('AQUATONEPATH', "~/aquatone")).expand_user()
ZDNS = Path("~/go/bin/zdns").expand_user()
ALL_CHARS = string.ascii_letters + string.digits

parser = argparse.ArgumentParser()
parser.add_argument('--domain','-d', required='True')
parser.add_argument('--wordlist','-w', required='True', type=argparse.FileType('r'))
args = parser.parse_args()

alteration_words = get_alteration_words(args.wordlist)

# will write to the file if the check returns true
def write_domain(wp, full_url):
    wp.write(full_url+'\n')

def generate_bag_of_words(n):
    if "FUZZ" in n:
        return alteration_words
    else:
        return [n]

def fuzz_words_subdomains(list_urls, wp):
    for url in list_urls:
        ext = tldextract.extract(url.strip())

        # word - subdomain - domain
        m = [alteration_words, [url]]
        for listAnswer in itertools.product(*m):
            write_domain(wp, "-".join(listAnswer))
            write_domain(wp, ".".join(listAnswer))
            write_domain(wp, "".join(listAnswer))

        # subdomain - word - domain
        m = [[ext.subdomain], alteration_words]
        for listAnswer in itertools.product(*m):
        	write_domain(wp, "-".join(listAnswer) + "." + ext.domain + "." + ext.suffix)
        	write_domain(wp, ".".join(listAnswer) + "." + ext.domain + "." + ext.suffix)
        	write_domain(wp, "".join(listAnswer) + "." + ext.domain + "." + ext.suffix)

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

def get_zdns_wildcards(domain):
	random_string = "".join(choice(ALL_CHARS) for x in range(randint(24, 24)))
	p = Popen([ZDNS, 'alookup','--ipv4-lookup'], stdout=PIPE, stdin=PIPE, stderr=PIPE)
	i = random_string+"."+domain
	output = p.communicate(input=i)

	g = json.loads(output[0])
	if g['status'] == "NOERROR":
		return g['data']['ipv4_addresses']
	else:
		return []

def resolve_zdns(altered_domains, wildcards):
	results = {}

	p = Popen([ZDNS, 'alookup','--ipv4-lookup'], stdout=PIPE, stdin=PIPE, stderr=PIPE)
	output = p.communicate(input="\n".join(altered_domains))
	temp = output[0].splitlines()
	for l in temp:
		t = json.loads(str(l))
		if t['status'] == "NOERROR":
			ip = t['data']['ipv4_addresses']
			if [x for x in ip if x not in wildcards]:
				results[t['name']] = ip

	return results

def write_results(results):
	with open('altdns.json', 'w') as outfile:
		json.dump(results, outfile)

def main():
	path_domain = Path(AQUATONE_ROOT, args.domain)
	path_domain.chdir()

	print("Running Altdns for domain %s", args.domain)

	#hosts = read_hosts3("massdns-18-06-07.txt")
	hosts = read_hosts4("list.txt")
	print("Numbers of subdomains: %d", len(hosts))

	_, output_tmp = mkstemp()
	print("Tempfile is: %s", output_tmp)

	with open(output_tmp, 'a+') as wp:
	 	fuzz_words_subdomains(hosts, wp)

	#altered_domains = altdns.altdns( get_alteration_words(args.wordlist), hosts, True, True)
	#r = resolve(altered_domains, get_wildcards(args.domain))
	#print("Number of results: %s",len(r))
	#write_results(r)

if __name__ == "__main__":
    main()