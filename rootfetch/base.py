import urllib2
import json
import os
import sys
import subprocess
import urllib
import tempfile


class RootStoreFetcher(object):

    def __init__(self, temp_path="/tmp"):
        self.temp_path = temp_path

    def setup(self):
        pass

    def fetch(self, output_path):
        raise Exception("not implemented")

    def _make_temp_path(self, p):
        return os.path.join(self.temp_path, p)

    def _make_temp_directory(self, suffix):
        return tempfile.mkdtemp(suffix=suffix)
