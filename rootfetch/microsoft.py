# -*- coding: utf-8 -*-

import json
import subprocess
import sys
import urllib.request
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

    STL_URL = "http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authroot.stl"
    CERT_DIST_POINT = "http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/"

    def __init__(self):
        super(MicrosoftFetcher, self).__init__()
        self._parse_ctl_path = None

    @staticmethod
    def split(input, size):
        for start in range(0, len(input), size):
            yield input[start:start + size]

    def setup(self):
        self._parse_ctl_path = 'parsectl.pl'

    def parse_ctl(self, ctl):
        dist_points = []
        decoded_ctl = decoder.decode(ctl[63:], asn1Spec=CTL())[0]
        for entry in decoded_ctl['InnerCTL']:
            cert_id = binascii.hexlify(entry['CertID'].asOctets())
            dist_point = self.CERT_DIST_POINT + cert_id + ".crt"
            dist_points.append(dist_point)
        return dist_points

    def fetch(self, output):
        ctl = urllib.request.urlopen(self.STL_URL).read()
        dist_points = self.parse_ctl(ctl)
        for url in dist_points:
            pem = urllib.request.urlopen(url).read().encode("base64").strip().replace(
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
