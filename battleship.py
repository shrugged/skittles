import argparse
import wfuzz
import json
from unipath import Path
import time

parser = argparse.ArgumentParser()
parser.add_argument("-l", "--list",
                    help="List of apis",default="/home/shrug/wordlist/google_apis_pa_list.txt", type=argparse.FileType('r'))
parser.add_argument("-i", "--input",
                    help="List of apis", required=True)
parser.add_argument("-s", "--static",
                    help="List of static wordlist", default="/home/shrug/wordlist/static20")
parser.add_argument("-e", "--end",
                    help="List of static wordlist", default="/home/shrug/wordlist/dev_list.txt")
parser.add_argument("-o", "--output",
                    help="Output location for altered subdomains",default='-',
                    type=argparse.FileType('w'))


args = parser.parse_args()

def run_scan(pa):
	output = set() 
	URL = 'https://www.googleapis.com/$discovery'

	headers = [('X-Originating-IP', '127.0.0.1'),
            ('X-Forwarded-For', '127.0.0.1'),
            ('X-Remote-IP', '127.0.0.1'),
            ('X-Remote-Addr', '127.0.0.1'),
            ('Accept', '*/*'),
            ('Content-Type',  'application/json'),
            ('referer', 'www.googleapis.com'),
            ('Host', 'FUZZ-FUZ2ZFUZ3Z-googleapis.sandbox.google.com')]

	payloads=[("file",dict(fn=args.static)),("file",dict(fn=args.input)),("file",dict(fn=args.end))]

	with wfuzz.FuzzSession(scanmode=True, url=URL, hc=[404,'XXX'], headers=headers, payloads=payloads) as sess:
		for res in sess.fuzz():
			w = "".join(res.payload[1:]).lower()
			#args.output.write(w + "\n")
			if not w in pa and not w in output:
				output.add(w)
				args.output.write(w + "\n")

	return output

def main():
	pa = args.list.read().splitlines()
	scan = run_scan(pa)


if __name__ == "__main__":
	main()