import base64
import shutil
import os.path

import urllib2
from rootfetch.base import *

from bs4 import BeautifulSoup



class AppleFetcher(RootStoreFetcher):

    LIST_OF_TARBALLS_URL = "https://opensource.apple.com/tarballs/security_certificates/"
    PREPEND_PATH = "https://opensource.apple.com/tarballs/security_certificates"

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

    def get_latest_tarball(self):
        return "/".join([self.PREPEND_PATH,list(self.get_tarballs())[-1]])

    def make_pem(self, path):
        raw = open(path).read()
        stream = base64.b64encode(raw)
        yield "-----BEGIN CERTIFICATE-----"
        for l in self.split(stream, 64):
            yield l
        yield "-----END CERTIFICATE-----"

    def fetch(self, output):
        dl_path = self.get_latest_tarball()
        raw_path = self._make_temp_path("rootfetch-apple-raw")
        urllib.urlretrieve(dl_path, raw_path)
        # file is a gzipped tarball.
        extract_path = self._make_temp_path("rootfetch-apple-extracted")
        if os.path.exists(extract_path):
            shutil.rmtree(extract_path)
        os.mkdir(extract_path)
        cmd = "tar --strip-components 1 -xzvf %s -C %s 2> /dev/null" % (raw_path, extract_path)
        subprocess.check_output(cmd, shell=True)
        # alright, we now have a directory with all the apple files.
        # we need to find the roots directory, parse out all the different
        # formats, then generate a single file that has PEMs in it.
        path = os.path.join(extract_path, "certificates", "roots")
        for f in os.listdir(path):
            full_path = os.path.join(path, f)
            if not os.path.isfile(full_path):
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
