import base64
import shutil
import os.path

import urllib2
from rootfetch.base import *

from bs4 import BeautifulSoup


class CTFetcher(RootStoreFetcher):

    @staticmethod
    def split(input, size):
        for start in range(0, len(input), size):
            yield input[start:start+size]

    def get_tarballs(self):
        response = urllib2.urlopen(self.LIST_OF_TARBALLS_URL)
        html = response.read()
        soup = BeautifulSoup(html, "html.parser")
        for row in soup.body.find_all("table")[0].find_all("tr"):
            try:
                cells = row.find_all("td")
                if not cells:
                    continue
                href = cells[1].find_all("a")[0]["href"]
                if href.startswith("security_certificates"):
                    yield href
            except:
                pass

    def make_pem(self, raw):
        stream = base64.b64encode(raw)
        yield "-----BEGIN CERTIFICATE-----"
        for l in self.split(stream, 64):
            yield l
        yield "-----END CERTIFICATE-----"


    def get(self):
        return json.loads(urllib2.urlopen(self.URL).read())

    def fetch(self, output):
        for certificate in self.get()["certificates"]:
            pem = "\n".join(self.make_pem(certificate))
            output.write(pem)
            output.flush()
            print "\n"


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
    m = GoogleAviator()
    m.setup()
    m.fetch(sys.stdout)

