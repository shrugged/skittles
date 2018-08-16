from wfuzz.plugin_api.base import BasePlugin
from wfuzz.externals.moduleman.plugin import moduleman_plugin

import time
import random
import string
import os
import errno
import json

WFUZZ_REPORTS_DIR = os.environ['HOME'] + "/.wfuzz/reports"

import hashlib
m = hashlib.md5()

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
        date_dir += ''.join(random.choice(string.ascii_lowercase +
                                          string.digits) for _ in range(6))
        self.reports_dir = WFUZZ_REPORTS_DIR + "/" + date_dir + "/"
        mkdir_p(self.reports_dir)
        self.l = dict()
        print("Report dir is at: ", self.reports_dir)

    def __del__(self):
        print("Report dir is at: ", self.reports_dir)
        with open(self.reports_dir + "report.json", 'w') as fp:
            json.dump(self.l, fp)

    def validate(self, fuzzresult):
        return True

    def process(self, fuzzresult):
    	#rint(vars(fuzzresult))
    	#print(fuzzresult.md5)
    	m = hashlib.md5()
    	m.update(fuzzresult.history.content)
    	md5 = m.hexdigest()
    	#print(md5)
        if md5:
            file_name = self.reports_dir + md5
            host = fuzzresult.history.headers.request['Host']
            if host not in self.l:
                self.l[host] = dict()
            self.l[host].update({fuzzresult.description: md5})

            if not os.path.isfile(file_name):
            	write_raw_content(file_name, fuzzresult.history.raw_content)
