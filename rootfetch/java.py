# -*- coding: utf-8 -*-

import base64
import os
import os.path
import subprocess
import sys

import sh

from rootfetch.base import RootStoreFetcher, RootStoreFetchException


class JavaFetcher(RootStoreFetcher):
    """JaveFetcher exports the Jave SE root store from the JRE.

    JavaFetcher requires that $JAVA_HOME is set and valid."""

    TEST_COMMAND = """keytool -list -v -keystore {0!s}/jre/lib/security/cacerts -storepass 'changeit'"""
    LIST_CERTS_COMMAND = """keytool -list -v -keystore {0!s}/jre/lib/security/cacerts -storepass 'changeit' | grep "Alias name:" | awk '{{print $3}}'"""
    GET_CERT_COMMAND = """keytool -export -alias {!s} -file {!s} -keystore {!s}/jre/lib/security/cacerts -storepass 'changeit' 2> /dev/null"""

    DEFAULT_LINUX_JVM = "/usr/lib/jvm"

    def __init__(self, java_home=None, *args, **kwargs):
        super(JavaFetcher, self).__init__(args, kwargs)
        self._java_home = java_home

    def make_pem(self, path):
        with open(path) as fd:
            raw = fd.read()
        stream = base64.b64encode(raw)
        yield "-----BEGIN CERTIFICATE-----"
        for l in self.split(stream, 64):
            yield l
        yield "-----END CERTIFICATE-----"

    def setup(self, *args, **kwargs):
        super(JavaFetcher, self).setup(args, kwargs)
        java_home = self._find_java_home()
        if not java_home:
            raise RootStoreFetchException(
                "Could not determine $JAVA_HOME. Is $JAVA_HOME set correctly?")
        self._java_home = java_home
        self._test_java()

    def _find_java_home(self):
        if self._java_home:
            return self._java_home

        # First check if the enviornment variable is set.
        java_home = os.environ.get("JAVA_HOME", None)
        if java_home:
            return java_home

        # On OS X, there's a magical command that gives you $JAVA_HOME
        if sys.platform == "darwin":
            try:
                cmd = sh.Command("/usr/libexec/java_home")
                return cmd().strip()
            except sh.ErrorReturnCode:
                pass

        # If only one Java is installed in the default Linux JVM folder, use
        # that
        if sys.platform in {"linux", "linux2"}:
            if os.path.isdir(self.DEFAULT_LINUX_JVM):
                javas = os.listdir(self.DEFAULT_LINUX_JVM)
                if len(javas) == 1:
                    return javas[0]

        # Give up
        return None

    def _test_java(self):
        try:
            cmd = self.TEST_COMMAND.format(self._java_home)
            subprocess.check_output(cmd, shell=True)
        except subprocess.CalledProcessError:
            raise RootStoreFetchException(
                "Could not list keytool. Is $JAVA_HOME set correctly?")

    def get_certs(self):
        cmd = self.LIST_CERTS_COMMAND.format(self._java_home)
        o = subprocess.check_output(cmd, shell=True)
        for line in o.split("\n"):
            line = line.strip()
            if line != "":
                yield line.strip()

    def get_der(self, name):
        extract_path = self._make_temp_path("java_extract")
        cmd = self.GET_CERT_COMMAND.format(name, extract_path, self._java_home)
        subprocess.check_output(cmd, shell=True)
        return extract_path

    def fetch(self, output):
        certs = self.get_certs()
        if not certs:
            raise RootStoreFetchException(
                "Unable to dump cacerts store. Is JAVA_HOME set correctly?")
        for cert in certs:
            der = self.get_der(cert)
            pem = self.make_pem(der)
            output.write("\n".join(pem))
            output.write("\n")


if __name__ == "__main__":
    m = JavaFetcher()
    m.setup()
    m.fetch(sys.stdout)
