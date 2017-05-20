# -*- coding: utf-8 -*-

import json
import sys
import urllib2

from rootfetch.base import RootStoreFetcher


class CTFetcher(RootStoreFetcher):

    URL = None

    def make_pem(self, raw):
        yield "-----BEGIN CERTIFICATE-----"
        for l in self.split(raw, 64):
            yield l
        yield "-----END CERTIFICATE-----"

    def get(self):
        return json.loads(urllib2.urlopen(self.URL).read())

    def fetch(self, output):
        for certificate in self.get()["certificates"]:
            pem = "\n".join(self.make_pem(certificate))
            output.write(pem)
            output.write("\n")
            output.flush()


class GoogleAviator(CTFetcher):

    URL = "https://ct.googleapis.com/aviator/ct/v1/get-roots"


class GooglePilot(CTFetcher):

    URL = "https://ct.googleapis.com/pilot/ct/v1/get-roots"


class GoogleIcarus(CTFetcher):

    URL = "https://ct.googleapis.com/icarus/ct/v1/get-roots"


class GoogleRocketeer(CTFetcher):

    URL = "https://ct.googleapis.com/rocketeer/ct/v1/get-roots"


class GoogleSkydiver(CTFetcher):

    URL = "https://ct.googleapis.com/skydiver/ct/v1/get-roots"


if __name__ == "__main__":
    m = GooglePilot()
    m.setup()
    m.fetch(sys.stdout)
