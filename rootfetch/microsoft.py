from rootfetch.base import *


class MicrosoftFetcher(RootStoreFetcher):

    PARSECTL_URL = "https://raw.githubusercontent.com/eabalea/MicrosoftRootProgram/master/parsectl.pl"
    CAB_URL = "http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab"


    @property
    def _parse_ctl_path(self):
        return self._make_temp_path("rootfetch-microsoft-parsectl")

    def setup(self):
        try:
            subprocess.check_call("perl --version > /dev/null", shell=True)
        except:
            raise Exception("perl not installed")
        try:
            subprocess.check_call("cabextract --version > /dev/null", shell=True)
        except:
            raise Exception("cabextract not installed")
        urllib.urlretrieve(self.PARSECTL_URL, self._parse_ctl_path)

    @staticmethod
    def split(input, size):
        for start in range(0, len(input), size):
            yield input[start:start+size]

    def fetch(self, output):
        cab_path = self._make_temp_path("rootfetch-microsoft-cab")
        urllib.urlretrieve(self.CAB_URL, cab_path)
        cabe_path = self._make_temp_path("rootfetch-microsoft-cab-extracted")
        subprocess.check_call("cabextract -p %s > %s" % (cab_path, cabe_path), shell=True)
        asn_path = self._make_temp_path("rootfetch-microsoft-cab-asn")
        cmd = "openssl asn1parse -inform D -in %s -strparse 63 -out %s > /dev/null 2>&1" % (cabe_path, asn_path)
        subprocess.check_call(cmd, shell=True)
        res = subprocess.check_output("perl %s %s" % (self._parse_ctl_path,
            asn_path), shell=True)
        for cert in json.loads(res)["InnerCTL"]:
            url = cert["URLToCert"]
            output.write("# ")
            output.write(str(cert))
            output.write("\n")
            pem = urllib2.urlopen(url).read().encode("base64").strip().replace("\t","").replace(" ","").replace("\n","")
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
