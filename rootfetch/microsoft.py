import base64
import json
import subprocess
import sys
import urllib.request
import binascii
from cryptography.hazmat.primitives.serialization import pkcs7
from pyasn1.type import univ, namedtype, useful, tag
from pyasn1.codec.ber import decoder

from rootfetch.base import RootStoreFetcher, RootStoreFetchException


OID_SIGNED_DATA = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 7, 2))
OID_CTL = univ.ObjectIdentifier((1, 3, 6, 1, 4, 1, 311, 10, 1))


def context_tag(number, constructed=True):
    return tag.Tag(
        tag.tagClassContext,
        tag.tagFormatConstructed if constructed else tag.tagFormatSimple,
        number
    )


class AlgorithmIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('oid', univ.ObjectIdentifier()),
        namedtype.NamedType('params', univ.Null()),
    )


class ContentInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('contentType',  univ.ObjectIdentifier()),
        namedtype.NamedType('content', univ.Any().subtype(explicitTag=context_tag(0))),
    )


class SignedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer()),
        namedtype.NamedType('digestAlgorithms', univ.Any()),
        namedtype.NamedType('contentInfo', ContentInfo()),
        namedtype.OptionalNamedType(
            'certificates',
            univ.SequenceOf(componentType=univ.Any()).subtype(
                implicitTag=context_tag(0))),
        namedtype.OptionalNamedType(
            'crls',
            univ.SequenceOf(componentType=univ.Any()).subtype(
                implicitTag=context_tag(1))),
        namedtype.NamedType('signerInfos', univ.Any()),
    )


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
        content_info = decoder.decode(ctl, asn1Spec=ContentInfo())[0]
        if content_info['contentType'] != OID_SIGNED_DATA:
            raise ValueError(
                'Top-level ContentInfo had type %s instead of signedData' %
                content_info['contentType'])
        signed_data = decoder.decode(content_info['content'],
                                     asn1Spec=SignedData())[0]
        if signed_data['contentInfo']['contentType'] != OID_CTL:
            raise ValueError(
                'Inner ContentInfo had type %s instead of szOID_CTL' %
                signed_data['contentInfo']['contentType'])
        decoded_ctl = decoder.decode(signed_data['contentInfo']['content'],
                                     asn1Spec=CTL())[0]
        for entry in decoded_ctl['InnerCTL']:
            cert_id = entry['CertID'].asOctets().hex()
            print(cert_id)
            dist_point = self.CERT_DIST_POINT + cert_id + ".crt"
            dist_points.append(dist_point)
        return dist_points

    def fetch(self, output):
        ctl = urllib.request.urlopen(self.STL_URL).read()
        dist_points = self.parse_ctl(ctl)
        for url in dist_points:
            der = urllib.request.urlopen(url).read()
            b64 = base64.b64encode(der)
            pem = b64.decode('utf-8').strip().replace("\t", "").replace(" ", "").replace("\n", "")
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
