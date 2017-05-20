# -*- coding: utf-8 -*-

import subprocess
import sys
import urllib

from rootfetch.base import RootStoreFetcher


class MozillaFetcher(RootStoreFetcher):
    """MozillaFetcher fetches the NSS root store from the HEAD of the NSS
    source repository"""

    MOZILLA_URL = "https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt"

    def fetch(self, output):
        raw_path = self._make_temp_path("rootfetch-mozilla-raw")
        urllib.urlretrieve(self.MOZILLA_URL, raw_path)
        output_path = self._make_temp_path("rootfetch-microsoft-cab-extracted")
        cmd = "extract-nss-root-certs {!s} > {!s}".format(
            raw_path, output_path)
        subprocess.check_call(cmd, shell=True)
        with open(output_path) as fd:
            output.write(fd.read())


if __name__ == "__main__":
    m = MozillaFetcher()
    m.setup()
    m.fetch(sys.stdout)
