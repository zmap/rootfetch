import base64

from rootfetch.base import *

class JavaFetcher(RootStoreFetcher):


    TEST_COMMAND = """keytool -list -v -keystore $JAVA_HOME/jre/lib/security/cacerts -storepass 'changeit'"""
    LIST_CERTS_COMMAND = """keytool -list -v -keystore $JAVA_HOME/jre/lib/security/cacerts -storepass 'changeit' | grep "Alias name:" | awk '{print $3}'"""
    GET_CERT_COMMAND = """keytool -export -alias %s -file %s -keystore $JAVA_HOME/jre/lib/security/cacerts -storepass 'changeit' 2> /dev/null"""

    @staticmethod
    def split(input, size):
        for start in range(0, len(input), size):
            yield input[start:start+size]

    def make_pem(self, path):
        raw = open(path).read()
        stream = base64.b64encode(raw)
        yield "-----BEGIN CERTIFICATE-----"
        for l in self.split(stream, 64):
            yield l
        yield "-----END CERTIFICATE-----"

    def test_java(self):
        subprocess.check_output(self.TEST_COMMAND, shell=True)

    def get_certs(self):
        o = subprocess.check_output(self.LIST_CERTS_COMMAND, shell=True)
        for line in o.split("\n"):
            line = line.strip()
            if line != "":
                yield line.strip()

    def get_der(self, name):
        extract_path = self._make_temp_path("java_extract")
        cmd = self.GET_CERT_COMMAND % (name, extract_path)
        subprocess.check_output(cmd, shell=True)
        return extract_path

    def fetch(self, output):
        self.test_java()
        certs = self.get_certs()
        if not certs:
            raise Exception("Unable to dump cacerts store. Is JAVA_HOME set correctly?")
        for cert in certs:
            output.write("\n".join(self.make_pem(self.get_der(cert))))
            output.write("\n\n")


if __name__ == "__main__":
    m = JavaFetcher()
    m.setup()
    m.fetch(sys.stdout)
