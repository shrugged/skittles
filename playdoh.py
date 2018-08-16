import argparse
import wfuzz
import json
from unipath import Path
import time

API_KEYS = [
#	("AIzaSyB5V4SIBGmrqREm7kf2fBJgPcBMCdUrLzE","yes") #sandbox keep
#	("AIzaSyCxLGKtpCiOT3y-3MwNQu4FL3XtDfsonz0", "yes") # my key
	("AIzaSyCI-zsRP85UVOi0DjtiCwWBwQ1djDy741g", "console.cloud.google.com"),
	("AIzaSyD-a9IF8KKYgoC3cpgS-Al7hLQDbugrDcw", "apis-explorer.appspot.com")
	# ("AIzaSyA8eiZmM1FaDVjRy-df2KTyQ_vz_yYM39w", "ok"),
	# ("AIzaSyAApHi-MvLY-vA4xRiTHAvnEW-4OikJ1iU", "ok"),
	# ("AIzaSyAIE8P709QB4ZYNMxjgH0_Tsa7b0DScshs", "ok"),
	# ("AIzaSyAMX775bK7F5ciFA6w9pXNJyvzqcSPeHH0", "ok"),
	# ("AIzaSyAXdDnif6B7sBYxU8hzw9qAp3pRPVHs060", "ok"),
	# ("AIzaSyAYfoSs86LzFMXNWJhyeGtZp0ijdZb_uGU", "ok"),
	# ("AIzaSyAaW_MDe2gZRngxQVO5TPw8KCQLKxaoRbM", "ok"),
	# ("AIzaSyAgN8jyeXINVgzycsEwCBVemudTlzEzv9k", "ok"),
	# ("AIzaSyAinVAlX3P0WtY-20Qga1knUxQJVMK9ER0", "ok"),
	# ("AIzaSyAri0oTuT61k36C0mAh9ksMzDseaY_Lt6Q", "ok"),
	# ("AIzaSyAtG6HdBweIA0RZuqbaL323-GzJxCe1bKE", "ok"),
	# ("AIzaSyAxxQKWYcEX8jHlflLt2Qcbb-rlolzBhhk", "ok"),
	# ("AIzaSyBFjW3MeNE9P_CXiRBTLWWCAO9yN3Ftp00", "ok"),
	# ("AIzaSyBK6MmN29Pi3wq8XFUBhmukENGaH5_tGXw", "ok"),
	# ("AIzaSyBOti4mM-6x9WDnZIjIeyEU21OpBXqWBgw", "ok"),
	# ("AIzaSyBdEFvybu3pLLqPgu8m3MvsdScdKFfD6vE", "ok"),
	# ("AIzaSyBfLlvWYndiQ3RFEHli65qGQH36QIxdyCI", "ok"),
	# ("AIzaSyC76tuQkztPY3i4JmVm0WzeaKlgL0tudCI", "ok"),
	# ("AIzaSyCB5sc4sgRVObMraVTM-ymBkANcjiQXcV0", "ok"),
	# ("AIzaSyCONWwd3ddhTfZlO1zD3OduQ7aVJae8A8U", "ok"),
	# ("AIzaSyCVl7z2EZZ1S1mbhW_beZ1cELoLreBMECM", "ok"),
	# ("AIzaSyCbNu0kKlAVm5mL6m4NUEgCUl0NR3nPqLs", "ok"),
	# ("AIzaSyCfNwlXWX_Zdn9EaRh2ZqmweUEiEpVWW_M", "ok"),
	# ("AIzaSyCjc_pVEDi4qsv5MtC2dMXzpIaDoRFLsxw", "ok"),
	# ("AIzaSyD6rHISplxB0FpFkiWAm2PmZvR905z676k", "ok"),
	# ("AIzaSyD7RkygokPHach6FGGEeoIA4rxo_WkoFzc", "ok"),
	# ("AIzaSyDBmyHulletPuU1s3beE-ZOB1IxKK0lxxw", "ok"),
	# ("AIzaSyDEG3F3Q4aovbmuvbPyUn-wj8PaRHiTi9A", "ok"),
	# ("AIzaSyDEabslTraNEB9Tn0sKiJuSyoUN5Uebus8", "ok"),
	# ("AIzaSyDEyIUMKSiOW-j3IqAzerwecUE4nfFBnfY", "ok"),
	# ("AIzaSyDP-ww8Di_cGZ0zcTHcECQY4sz20LSS-Mg", "ok"),
	# ("AIzaSyDRKQ9d6kfsoZT2lUnZcZnBYvH69HExNPE", "ok"),
	# ("AIzaSyDVnIvX76kibsBvpPBINVleuJc1jcUOZkM", "ok"),
	# ("AIzaSyDXpRqQ0l7qLZgcsNRLs14Lk9CDUMbYOwc", "ok"),
	# ("AIzaSyDZbWNBK81yJVvpc5wRfCLwPyLYsGpwRbQ", "ok"),
	# ("AIzaSyD_qjV8zaaUMehtLkrKFgVeSX_Iqbtyws8", "ok"),
	# ("AIzaSyDaQPK_rJmlblF1_zAJfaZrfWK26lsxMwc", "ok"),
	# ("AIzaSyDbHU30I-v5OpOJm1-uff09-NJbd6I8InU", "ok"),
	# ("AIzaSyDhHeH9rQeGb2XZk_HIc0N6vJGLOOy21eY", "ok"),
	# ("AIzaSyDilkmWdiwxQBQnAap6hbchryy4RWcECLg", "ok"),
	# ("AIzaSyDl0hwvpSdvlqb6fb0Z5UubNkvTUiu9pJg", "ok"),
	# ("AIzaSyDnzzH422P-9NdbzaNxJ2ywsZqjbA3oDFQ", "ok"),
	# ("AIzaSyDtkMBS0CUrKdTOSQUp7p5K1RcB4qenxZU", "ok"),
	# ("AIzaSyDwzOp5nlDuTO2MtXeMek6aD5e6rQs49Mk", "ok"),
	# ("AIzaSyDzSyl-DPNxSyc7eghRsB4oNNetrnvnH0I", "ok")
]

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--input",
                    help="List of apis",default="/home/shrug/wordlist/google_apis_pa_list.txt")
parser.add_argument("-s", "--static",
                    help="List of static wordlist", default="/home/shrug/wordlist/static5")
parser.add_argument("-o", "--output",
                    help="List of static wordlist", default="/home/shrug/$discovery")

args = parser.parse_args()

def setup_dir(dir):
	report_dir = Path(dir)
	report_dir.mkdir(parents=True)
	prod = Path(report_dir, "prod")
	prod.mkdir()
	sandbox = Path(report_dir, "sandbox")
	sandbox.mkdir()

	return report_dir

def save_discovery(d, res):
	f = d + "/" + "-".join(res.payload)
	data = json.loads(res.history.content)

	with open(f, 'wb') as outfile:
		json.dump(data, outfile, indent=4, sort_keys=True, separators=(',', ': '), ensure_ascii=True)

def run_scan(apikey, referer, output):
	URL = 'https://www.googleapis.com/$discovery/rest?key=' + apikey

	headers = [('X-Originating-IP', '127.0.0.1'),
            ('X-Forwarded-For', '127.0.0.1'),
            ('X-Remote-IP', '127.0.0.1'),
            ('X-Remote-Addr', '127.0.0.1'),
            ('Accept', '*/*'),
            ('Content-Type',  'application/json')]


	headers.append(("referer", referer))

	with wfuzz.FuzzSession(scanmode=True, url=URL, sc=[200]) as sess:
		#prod
		headers.append(("Host", "FUZZ.googleapis.com"))
		payloads=[("file",dict(fn=args.input))]

		for res in sess.fuzz(headers=headers, payloads=payloads):
			save_discovery(output + "/prod", res)

		#sandbox
		headers.append(("Host", "FUZ2Z-FUZZ-googleapis.sandbox.google.com"))
		payloads=[("file",dict(fn=args.input)), ("file",dict(fn=args.static))]
		for res in sess.fuzz(headers=headers, payloads=payloads):
			save_discovery(output + "/sandbox", res)

def main():
	for b in API_KEYS:
		d = setup_dir(args.output + "/" + b[0])
		print(d)
		run_scan(b[0], b[1], d)

if __name__ == "__main__":
	main()