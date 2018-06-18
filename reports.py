from wfuzz.plugin_api.base import BasePlugin
from wfuzz.externals.moduleman.plugin import moduleman_plugin

import time
import random
import string
import os
import errno
import json

WFUZZ_REPORTS_DIR = os.environ['HOME'] + "/.wfuzz/reports"

def mkdir_p(path):
    """ 'mkdir -p' in Python """
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

def write_raw_content(f, content):
    	with open(f, "w") as f:
    		#print("writelines: %s", name)
    		f.writelines(content)

@moduleman_plugin
class reports(BasePlugin):
    name = "reports"
    author = ("Shrug",)
    version = "0.1"
    summary = "Keep a record of everything."
    category = ["active"]
    priority = 1

    parameters = (
    )

    def __init__(self):
        BasePlugin.__init__(self)
        date_dir = time.strftime('%y-%m-%d')
        date_dir += "-"
        date_dir += ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6))
        self.reports_dir = WFUZZ_REPORTS_DIR + "/" + date_dir + "/"
        mkdir_p(self.reports_dir)
        self.l = dict()

    def __del__(self):
    	with open(self.reports_dir + "report.json", 'w') as fp:
    		json.dump(self.l, fp)

    def validate(self, fuzzresult):
        return True

    def process(self, fuzzresult):
    	file_name = self.reports_dir + fuzzresult.md5
    	host = fuzzresult.history.headers.request['Host']
    	if not host in self.l:
    		self.l[host] = dict()
    	self.l[host].update({fuzzresult.description : fuzzresult.md5})
    	write_raw_content(file_name, fuzzresult.history.raw_content)
    	
