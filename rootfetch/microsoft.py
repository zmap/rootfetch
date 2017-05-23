# -*- coding: utf-8 -*-

import json
import subprocess
import sys
import urllib
import urllib2

from rootfetch.base import RootStoreFetcher, RootStoreFetchException


class MicrosoftFetcher(RootStoreFetcher):
    """MicrosoftFetcher fetches the latest root store from Windows Update"""

    PARSECTL_URL = "https://raw.githubusercontent.com/eabalea/MicrosoftRootProgram/master/parsectl.pl"
    CAB_URL = "http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab"

    def __init__(self):
        super(MicrosoftFetcher, self).__init__()
        self._parse_ctl_path = None

    @staticmethod
    def split(input, size):
        for start in range(0, len(input), size):
            yield input[start:start + size]

    def setup(self):
        try:
            subprocess.check_call("perl --version > /dev/null", shell=True)
        except subprocess.CalledProcessError as e:
            raise RootStoreFetchException("perl not installed")
        try:
            subprocess.check_call(
                "cabextract --version > /dev/null", shell=True)
        except subprocess.CalledProcessError as e:
            raise RootStoreFetchException("cabextract not installed")
        self._parse_ctl_path, _ = urllib.urlretrieve(self.PARSECTL_URL)

    def fetch(self, output):
        cab_path, _ = urllib.urlretrieve(self.CAB_URL)
        extract_path = self._make_temp_path(
            "rootfetch-microsoft-cab-extracted")
        extract_cmd = "cabextract -p {!s} > {!s}".format(
            cab_path, extract_path)
        subprocess.check_call(extract_cmd, shell=True)
        asn_path = self._make_temp_path("rootfetch-microsoft-cab-asn")
        cmd = "openssl asn1parse -inform D -in {!s} -strparse 63 -out {!s} > /dev/null 2>&1".format(
            extract_path, asn_path)
        subprocess.check_call(cmd, shell=True)
        res = subprocess.check_output("perl %s %s" % (self._parse_ctl_path,
                                                      asn_path), shell=True)
        res = unicode(res.strip(), encoding="utf-8", errors="replace")
        for cert in json.loads(res)["InnerCTL"]:
            url = cert["URLToCert"]
            output.write("# ")
            output.write(json.dumps(cert))
            output.write("\n")
            pem = urllib2.urlopen(url).read().encode("base64").strip().replace(
                "\t", "").replace(" ", "").replace("\n", "")
            output.write("-----BEGIN CERTIFICATE-----\n")
            for l in self.split(pem, 64):
                output.write(l)
                output.write("\n")
            output.write("-----END CERTIFICATE-----\n\n")
            output.flush()


if __name__ == "__main__":
    m = MicrosoftFetcher()
    m.setup()
    m.fetch(sys.stdout)
