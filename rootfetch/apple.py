import urllib2
from rootfetch.base import *

from bs4 import BeautifulSoup


class AppleFetcher(RootStoreFetcher):

    LIST_OF_TARBALLS_URL = "https://opensource.apple.com/tarballs/security_certificates/"
    PREPEND_PATH = "https://opensource.apple.com/tarballs/security_certificates"

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

    def make_pem_from(self, path):
        pass

    def make_root_store_from_directory(self, path):
        pass

    def fetch(self, output):
        dl_path = self.get_latest_tarball()
        raw_path = self._make_temp_path("rootfetch-apple-raw")
        urllib.urlretrieve(dl_path, raw_path)
        # file is a gzipped tarball.
        extract_path = self._make_temp_path("rootfetch-apple-raw")
        cmd = "tar -xzvf %s -C %s" % (raw_path, extract_path)
        subprocess.check_output(cmd, shell=True)
        # alright, we now have a directory with all the apple files.
        # we need to find the roots directory, parse out all the different
        # formats, then generate a single file that has PEMs in it.



if __name__ == "__main__":
    m = AppleFetcher()
    m.setup()
    m.fetch(sys.stdout)
