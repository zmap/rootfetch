# -*- coding: utf-8 -*-

import json
import subprocess
import sys
import urllib
import urllib2
import binascii
from pyasn1.type import univ, namedtype, useful
from pyasn1.codec.ber import decoder

from rootfetch.base import RootStoreFetcher, RootStoreFetchException

# ASN1 type for the metadata of a single entry in a Microsoft Certificate List
class CertMetaData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('MetaDataType', univ.ObjectIdentifier()),
        namedtype.NamedType('MetaDataValue', univ.Set(
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('RealContent', univ.OctetString())
        )))
    )

# ASN1 type for a single entry in a Microsoft Certificate List
class CTLEntry(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('CertID', univ.OctetString()),
        namedtype.NamedType('MetaData', univ.SetOf(CertMetaData())),
        )

# ASN1 type for Microsoft Certificate List
class CTL(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('dummy1', univ.Any()),
        namedtype.NamedType('UnknownInt', univ.Integer()),
        namedtype.NamedType('GenDate', useful.UTCTime()),
        namedtype.NamedType('dummy4', univ.Any()),
        namedtype.NamedType('InnerCTL', univ.SequenceOf(CTLEntry())),
        )

class MicrosoftFetcher(RootStoreFetcher):
    """MicrosoftFetcher fetches the latest root store from Windows Update"""

    CAB_URL = "http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab"
    CERT_DIST_POINT = "http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/"

    def __init__(self):
        super(MicrosoftFetcher, self).__init__()
        self._parse_ctl_path = None

    @staticmethod
    def split(input, size):
        for start in range(0, len(input), size):
            yield input[start:start + size]

    def setup(self):
        try:
            subprocess.check_call(
                "cabextract --version > /dev/null", shell=True)
        except subprocess.CalledProcessError as e:
            raise RootStoreFetchException("cabextract not installed")
        self._parse_ctl_path = 'parsectl.pl'

    def parse_ctl(self, ctlpath):
        dist_points = []
        with open(ctlpath, "rb") as ctl_file:
            ctl = ctl_file.read()
            decoded_ctl = decoder.decode(ctl, asn1Spec=CTL())[0]
            for entry in decoded_ctl['InnerCTL']:
                cert_id = binascii.hexlify(entry['CertID'].asOctets())
                dist_point = self.CERT_DIST_POINT + cert_id + ".crt"
                dist_points.append(dist_point)
        return dist_points

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
        dist_points = self.parse_ctl(asn_path)
        for url in dist_points:
            pem = urllib2.urlopen(url).read().encode("base64").strip().replace(
                "\t", "").replace(" ", "").replace("\n", "")
            output.write("-----BEGIN CERTIFICATE-----\n")
            for l in self.split(pem, 64):
                output.write(l)
                output.write("\n")
            output.write("-----END CERTIFICATE-----\n")
            output.flush()


if __name__ == "__main__":
    m = MicrosoftFetcher()
    m.setup()
    m.fetch(sys.stdout)
