from wfuzz.plugin_api.base import BasePlugin
from wfuzz.externals.moduleman.plugin import moduleman_plugin

@moduleman_plugin
class reports(BasePlugin):
    name = "ok"
    category = ["ok"]
    version = "1"
    summary = "Test"
    priority = 55

    parameters = (
    )

    def __init__(self):
        BasePlugin.__init__(self)
        print("init")

    def validate(self, fuzzresult):
        return True

    def process(self, fuzzresult):
    	print(fuzzresult.md5)