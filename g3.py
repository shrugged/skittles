import argparse
import wfuzz
import logging
from wt_utils import *

from termcolor import colored
from google.cloud import storage
from google.api_core import exceptions

from tempfile import mkstemp
import sys

BLACKLIST = ['.storage.googleapis.com',
			'.commondatastorage.googleapis.com']

logging.basicConfig(level=logging.CRITICAL)

parser = argparse.ArgumentParser(description='Bruteforce webservers')
parser.add_argument('--domain', required='True')
parser.add_argument('--blacklist',action='append')
parser.add_argument('--whitelist',action='append')
parser.add_argument('--list-files', action='store_true', default=False)

args = parser.parse_args()

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
                #results.append(r.description)

            if r.code != 400 and r.code != -1:
            	if args.list_files:
	                try:
	                    report_files_buckets(r.description)
	                except KeyboardInterrupt:
	                	pass
	                except Exception, e:
	                    print("Error listing files: " + str(e))

    print("Took %d seconds.", int(sess.stats.totaltime))
    return results

def list_bucket(bucket_name):
    l = []
    """Lists all the blobs in the bucket."""
    storage_client = storage.Client()
    # lowercase because it doesn't work otherwise
    for bl in BLACKLIST:
    	if bl in bucket_name:
    		bucket_name = bucket_name.replace(bl, '')

    bucket = storage_client.get_bucket(bucket_name.lower())

    blobs = bucket.list_blobs()
    for blob in blobs:
    	try:
        	l.append(str(blob.name.encode('utf-8'))+"\n")
        except UnicodeEncodeError:
        	pass

    return l

def report_files_buckets(name):
    path = os.path.expanduser('~/lazy')
    l = list_bucket(name)
    if l:
        with open(path + "/"+name, "w") as wp:
            wp.writelines(l)
        print("Number of files: %d", len(l))

# starting with . is illegal name
def filter_hosts(hosts):
	return [elem for elem in hosts if not elem[0] == '.' or elem[0] == '_']

def main():
	#print(os.environ['GOOGLE_APPLICATION_CREDENTIALS'])
	go_home(args.domain)
	print("Using domain: %s", args.domain)

	#hosts = read_hosts("hosts.json")
	#hosts = read_hosts2("subfinder.json")
	hosts = read_hosts4("subfinder-18-05-29.txt")
	hosts = filter_hosts(hosts)

	if len(hosts) == 0:
		sys.exit(0)

	print("Number of hosts: %d", len(hosts))

	_, output_tmp = mkstemp()
	with open(output_tmp, "w") as wp:
		for host in hosts:
			wp.write(host + "\n")

	bf = brute_force(output_tmp)

	if len(bf) > 0:
		print("Number of results: %s", len(bf))
		with open("g3.txt", "w") as wp:
			for l in bf:
				try:
					wp.write(str(l)+"\n")
				except UnicodeEncodeError:
					pass


if __name__ == "__main__":
    main()