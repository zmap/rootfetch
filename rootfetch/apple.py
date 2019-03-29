# -*- coding: utf-8 -*-

import base64
import os.path
import sys
import urllib
import urllib2

from rootfetch.base import RootStoreFetcher

from bs4 import BeautifulSoup
import sh


class AppleFetcher(RootStoreFetcher):

    LIST_OF_TARBALLS_URL = "https://opensource.apple.com/tarballs/security_certificates/"
    PREPEND_PATH = "https://opensource.apple.com/tarballs/security_certificates"

    @staticmethod
    def split(s, size):
        for start in range(0, len(s), size):
            yield s[start:start + size]

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
            except (KeyError, IndexError):
                pass

    def get_latest_tarball(self):
        return "/".join([self.PREPEND_PATH, list(self.get_tarballs())[-1]])

    def make_pem(self, path):
        with open(path) as fd:
            raw = fd.read()
        stream = base64.b64encode(raw)
        yield "-----BEGIN CERTIFICATE-----"
        for l in self.split(stream, 64):
            yield l
        yield "-----END CERTIFICATE-----"

    def fetch(self, output):
        dl_path = self.get_latest_tarball()
        raw_path, _ = urllib.urlretrieve(dl_path)

        # The downloaded file is a gzip'd tarball.
        extract_path = self._make_temp_directory("rootfetch-apple-extracted")
        sh.tar("-xzv", "-f", raw_path, "-C", extract_path, strip_components=1)

        # We now have a directory with all the apple files. We need to find the
        # roots directory, parse out all the different formats, then generate a
        # single file that has PEMs in it.
        certificates_path = os.path.join(extract_path, "certificates", "roots")
        for f in os.listdir(certificates_path):
            full_path = os.path.join(certificates_path, f)
            if not os.path.isfile(full_path):
                continue
            # Skip hidden files, such as .cvsignore
            if f.startswith('.'):
                continue
            pem = self.make_pem(full_path)
            output.write("# ")
            output.write(f)
            output.write("\n")
            output.write("\n".join(pem))
            output.write("\n\n")


if __name__ == "__main__":
    m = AppleFetcher()
    m.setup()
    m.fetch(sys.stdout)
