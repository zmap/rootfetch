# -*- coding: utf-8 -*-

import os.path
import subprocess
import sys
import urllib

from rootfetch.base import RootStoreFetcher, RootStoreFetchException


class MozillaFetcher(RootStoreFetcher):
    """MozillaFetcher fetches the NSS root store from the HEAD of the NSS
    source repository"""

    MOZILLA_URL = "https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt"

    def __init__(self):
        super(MozillaFetcher, self).__init__()
        here = os.path.dirname(__file__)
        bin_dir = os.path.join(here, "bin")
        if sys.platform == "darwin":
            bin_name = "extract-nss-root-certs-mac"
        elif sys.platform in {"linux", "linux2"}:
            bin_name = "extract-nss-root-certs-linux"
        else:
            msg = "unsupported platform {!s}".format(sys.platform)
            raise RootStoreFetchException(msg)
        self._cmd = os.path.join(bin_dir, bin_name)

    def fetch(self, output):
        raw_path, _ = urllib.urlretrieve(self.MOZILLA_URL)
        output_path = self._make_temp_path("rootfetch-mozilla-extracted")
        cmd = "{!s} {!s} > {!s}".format(self._cmd, raw_path, output_path)
        subprocess.check_call(cmd, shell=True)
        with open(output_path) as fd:
            output.write(fd.read())


if __name__ == "__main__":
    m = MozillaFetcher()
    m.setup()
    m.fetch(sys.stdout)
