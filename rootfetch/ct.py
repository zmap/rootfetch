# -*- coding: utf-8 -*-

import json
import sys
import urllib

from rootfetch.base import RootStoreFetcher


class CTFetcher(RootStoreFetcher):
    """CTFetcher fetches the root store from a Certificate Transparency log.

    The CT log server must comply to V1 of the CT API (RFC 6962). Subclass to
    define the log server URL."""

    URL = None

    def make_pem(self, raw):
        yield "-----BEGIN CERTIFICATE-----"
        for l in self.split(raw, 64):
            yield l
        yield "-----END CERTIFICATE-----"

    def get(self):
        return json.loads(urllib.request.urlopen(self.URL).read())

    def fetch(self, output):
        for certificate in self.get()["certificates"]:
            pem = "\n".join(self.make_pem(certificate))
            output.write(pem)
            output.write("\n")
            output.flush()


class CTUnionFetcher(RootStoreFetcher):
    """CTUnionFetcher fetches the root store from multiple Certificate Transparency logs and returns their union.

    The CT log servers must comply to V1 of the CT API (RFC 6962). Subclass to
    define the log server URL."""

    URLS = list()

    def make_pem(self, raw):
        yield "-----BEGIN CERTIFICATE-----"
        for l in self.split(raw, 64):
            yield l
        yield "-----END CERTIFICATE-----"

    def get(self, url):
        return json.loads(urllib.request.urlopen(url).read())

    def fetch(self, output):
        pems = set()
        for url in self.URLS:
            print(url)
            for certificate in self.get(url)["certificates"]:
                pems.add("\n".join(self.make_pem(certificate)))

        for pem in pems:
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


class GoogleXenon2023(CTFetcher):

    URL = "https://ct.googleapis.com/logs/xenon2023/ct/v1/get-roots"


class GoogleArgon2023(CTFetcher):

    URL = "https://ct.googleapis.com/logs/argon2023/ct/v1/get-roots"


class GoogleArgon2023UnionXenonUnionPilot(CTUnionFetcher):

    URLS = ["https://ct.googleapis.com/logs/argon2023/ct/v1/get-roots",
            "https://ct.googleapis.com/logs/xenon2023/ct/v1/get-roots",
            "https://ct.googleapis.com/pilot/ct/v1/get-roots"
    ]


if __name__ == "__main__":
    m = GoogleArgon2023UnionXenonUnionPilot()
    m.setup()
    m.fetch(sys.stdout)
