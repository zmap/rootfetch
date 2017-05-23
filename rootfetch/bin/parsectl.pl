#! /opt/local/bin/perl

use strict;
use utf8;

use Convert::ASN1 qw(:io :debug);
use JSON;
use Text::Iconv;
use Getopt::Std;
use DateTime;

my %opts;
getopts('t', \%opts);

# ASN.1 descriptions of the objects we're going to parse
my $asn = Convert::ASN1->new;
$asn->prepare(<<ASN1) or die "prepare: ", $asn->error;
   CTL ::= SEQUENCE {
     dummy1 ANY,
     UnknownInt INTEGER,
     GenDate UTCTime,
     dummy4 ANY,
     InnerCTL SEQUENCE OF CTLEntry
   }

   CTLEntry ::= SEQUENCE {
     CertID OCTET STRING,
     MetaData SET OF CertMetaData
   }

   CertMetaData ::= SEQUENCE {
     MetaDataType OBJECT IDENTIFIER,
     MetaDataValue SET {
       RealContent OCTET STRING
     }
   }

   EKUS ::= SEQUENCE OF OBJECT IDENTIFIER

   EVOIDS ::= SEQUENCE OF PolicyThing
   
   PolicyThing ::= SEQUENCE {
     EVOID OBJECT IDENTIFIER,
     dummy5 ANY
   }

ASN1

# Get a handle on particular ASN.1 objects decoders
my $asn_ctl = $asn->find('CTL');
my $asn_ctlentry = $asn->find('CTLEntry');
my $asn_ekus = $asn->find('EKUS');
my $asn_evoids = $asn->find('EVOIDS');
my $object = "";
my $converter = Text::Iconv->new("UTF-16LE", "UTF-8");

sub printctl {
  my ($ctl) = @_;

  if (defined $opts{'t'}) {
    my @Entries = @{$ctl->{'InnerCTL'}};
    @Entries = sort { $a->{'CertID'} cmp $b->{'CertID'} } @Entries;
    print "Entries: ", $#Entries, "\n";
    print "GenDate: ", $ctl->{'GenDate'}, "\n";
    print "UnknownInt: ", $ctl->{'UnknownInt'}, "\n";
    print "\n";

    foreach my $Entry (@Entries) {
      my %metadata;
      print "CertID: ", $Entry->{'CertID'}, "\n";
      print "URLToCert: ", $Entry->{'URLToCert'}, "\n";
      foreach my $MD (@{$Entry->{'MetaData'}}) {
        $metadata{'MetaEKUS'} = join(", ", sort @{$MD->{'MetaEKUS'}}) if defined $MD->{'MetaEKUS'};
        $metadata{'CertFriendlyName'} = $MD->{'CertFriendlyName'} if defined $MD->{'CertFriendlyName'};
        $metadata{'CertKeyIdentifier'} = $MD->{'CertKeyIdentifier'} if defined $MD->{'CertKeyIdentifier'};
        $metadata{'CertSubjectNameMD5Hash'} = $MD->{'CertSubjectNameMD5Hash'} if defined $MD->{'CertSubjectNameMD5Hash'};
        $metadata{'SHA256Digest'} = $MD->{'SHA256Digest'} if defined $MD->{'SHA256Digest'};
        $metadata{'EVOIDS'} = join(", ", sort @{$MD->{'EVOIDS'}}) if defined $MD->{'EVOIDS'};
        $metadata{'DisallowedOn'} = $MD->{'DisallowedOn'} if defined $MD->{'DisallowedOn'};
        $metadata{'PropID105'} = join(", ", sort @{$MD->{'PropID105'}}) if defined $MD->{'PropID105'};
        $metadata{'PropID122'} = join(", ", sort @{$MD->{'PropID122'}}) if defined $MD->{'PropID122'};
      }
      foreach my $metadata (sort keys %metadata) {
        print "$metadata: $metadata{$metadata}\n";
      }
      print "\n";
    }
  } else {
  print to_json($ctl, { pretty => 1 });
  }
}

sub friendlynameOID {
  my ($oid) = @_;

  $oid = "id-kp-serverAuth"      if ($oid eq "1.3.6.1.5.5.7.3.1");
  $oid = "id-kp-clientAuth"      if ($oid eq "1.3.6.1.5.5.7.3.2");
  $oid = "id-kp-codeSigning"     if ($oid eq "1.3.6.1.5.5.7.3.3");
  $oid = "id-kp-emailProtection" if ($oid eq "1.3.6.1.5.5.7.3.4");
  $oid = "id-kp-ipsecEndSystem"  if ($oid eq "1.3.6.1.5.5.7.3.5");
  $oid = "id-kp-ipsecTunnel"     if ($oid eq "1.3.6.1.5.5.7.3.6");
  $oid = "id-kp-ipsecUser"       if ($oid eq "1.3.6.1.5.5.7.3.7");
  $oid = "id-kp-timeStamping"    if ($oid eq "1.3.6.1.5.5.7.3.8");
  $oid = "id-kp-ocspSigning"     if ($oid eq "1.3.6.1.5.5.7.3.9");
  $oid = "iKEIntermediate"       if ($oid eq "1.3.6.1.5.5.8.2.2");
  $oid = "ms-EFS-CRYPTO"         if ($oid eq "1.3.6.1.4.1.311.10.3.4");
  $oid = "ms-EFS-RECOVERY"       if ($oid eq "1.3.6.1.4.1.311.10.3.4.1");
  $oid = "ms-DOCUMENT-SIGNING"   if ($oid eq "1.3.6.1.4.1.311.10.3.12");
  $oid = "ms-smartCardLogon"     if ($oid eq "1.3.6.1.4.1.311.20.2.2");
  $oid =~ s/1\.3\.6\.1\.4\.1\.311\.60\.3\.2/ROOT_PROGRAM_AUTO_UPDATE_END_REVOCATION/;
  $oid =~ s/1\.3\.6\.1\.4\.1\.311/OID-Microsoft/;

  return $oid;
}

sub convertFileTime {
  my ($binaryFT) = @_;
  my $HundredsNanoSec = unpack("Q<", $binaryFT);
  my $Seconds = $HundredsNanoSec / 10000000;

  my $dt = DateTime->new(
    year       => 1601,
    month      => 01,
    day        => 01,
    hour       => 00,
    minute     => 00,
    second     => 00,
    nanosecond => 00,
    time_zone  => 'floating');

  $dt->add( seconds => $Seconds );

  return $dt->day_abbr ." ". $dt->month_abbr ." ". $dt->day ." ". $dt->hms ." ". $dt->year;
}

# Read the whole CTL as a blob
while (<>) {
  $object = $object . $_;
}

# And try to decode it
my $ctl = $asn_ctl->decode($object);

if (defined $ctl) {
  # Delete unknown fields, and transform others
  delete $ctl->{'dummy1'};
  delete $ctl->{'dummy4'};
  $ctl->{'UnknownInt'} = uc($ctl->{'UnknownInt'}->as_hex());
  $ctl->{'GenDate'} = scalar gmtime($ctl->{'GenDate'});

  my @Entries = @{$ctl->{'InnerCTL'}};

  # We'll alter every CTL entry
  foreach my $Entry (@Entries) {
    # The CertID can be used to get the certificate
    my $CertID = uc(unpack("H*", $Entry->{'CertID'}));
    $Entry->{'CertID'} = $CertID;
    $Entry->{'URLToCert'} = "http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/".$CertID.".crt";

    # A set of properties is attached to every CTL entry, make them
    # more easily readable
    foreach my $MD (@{$Entry->{'MetaData'}}) {

      # OID_CERT_PROP_ID_METAEKUS
      if ($MD->{'MetaDataType'} eq "1.3.6.1.4.1.311.10.11.9")
      {
	my $ekus = $asn_ekus->decode($MD->{'MetaDataValue'}->{'RealContent'});
	foreach my $eku (@$ekus) {
	  $eku = friendlynameOID($eku);
	}
	$MD->{'MetaEKUS'} = $ekus; 
	delete $MD->{'MetaDataType'};
	delete $MD->{'MetaDataValue'};
      }

      # CERT_FRIENDLY_NAME_PROP_ID
      if ($MD->{'MetaDataType'} eq "1.3.6.1.4.1.311.10.11.11")
      {
        my $CertFriendlyName = $converter->convert($MD->{'MetaDataValue'}->{'RealContent'});
	$CertFriendlyName =~ s/\x00$//g;
	$MD->{'CertFriendlyName'} = $CertFriendlyName;
	delete $MD->{'MetaDataType'};
	delete $MD->{'MetaDataValue'};
      }

      # OID_CERT_KEY_IDENTIFIER_PROP_ID
      if ($MD->{'MetaDataType'} eq "1.3.6.1.4.1.311.10.11.20")
      {
        my $CertKeyIdentifier = uc(unpack("H*",	$MD->{'MetaDataValue'}->{'RealContent'}));
	$MD->{'CertKeyIdentifier'} = $CertKeyIdentifier;
	delete $MD->{'MetaDataType'};
	delete $MD->{'MetaDataValue'};
      }

      # OID_CERT_SUBJECT_NAME_MD5_HASH_PROP_ID
      if ($MD->{'MetaDataType'} eq "1.3.6.1.4.1.311.10.11.29")
      {
        my $CertSubjectNameMD5Hash = uc(unpack("H*", $MD->{'MetaDataValue'}->{'RealContent'}));
	$MD->{'CertSubjectNameMD5Hash'} = $CertSubjectNameMD5Hash;
	delete $MD->{'MetaDataType'};
	delete $MD->{'MetaDataValue'};
      }

      # CERT_ROOT_PROGRAM_CERT_POLICIES_PROP_ID
      if ($MD->{'MetaDataType'} eq "1.3.6.1.4.1.311.10.11.83")
      {
        # I think the "dummy5" element is here to indicate what type
	# of policy the OID is. Right now, I have encountered the same
	# value everywhere, and the OIDs are EV ones; let's ignore
	# "dummy5" and consider all these OIDs are EV ones.
	my @evoids;
	my $Thing = $asn_evoids->decode($MD->{'MetaDataValue'}->{'RealContent'});
	foreach my $policyprop (@$Thing) {
	  push @evoids, $policyprop->{'EVOID'};
	}
	$MD->{'EVOIDS'} = \@evoids;
	delete $MD->{'MetaDataType'};
	delete $MD->{'MetaDataValue'};
      }

      # OID_CERT_PROP_ID_PREFIX_98
      # Seems to be a SHA256 digest of the certificate (thanks @pzb)
      if ($MD->{'MetaDataType'} eq "1.3.6.1.4.1.311.10.11.98")
      {
        my $Thing = uc(unpack("H*", $MD->{'MetaDataValue'}->{'RealContent'}));
	$MD->{'SHA256Digest'} = $Thing;
	delete $MD->{'MetaDataType'};
	delete $MD->{'MetaDataValue'};
      }

      # OID_CERT_PROP_ID_PREFIX_104
      # May be future date disallow (Win10)
      # I consider this to be a 64bits little-endian Windows filetime
      # (100-nanoseconds interval that have elapsed since 12:00 AM
      # January 1, 1601 UTC)
      # Divide the number by 10000000, add this to the aforementioned
      # date, get the resulting UTC date. Leapseconds aren't probably counted.
      if ($MD->{'MetaDataType'} eq "1.3.6.1.4.1.311.10.11.104")
      {
	$MD->{'DisallowedOn'} = convertFileTime($MD->{'MetaDataValue'}->{'RealContent'});
	delete $MD->{'MetaDataType'};
	delete $MD->{'MetaDataValue'};
      }

      # OID_CERT_PROP_ID_PREFIX_105
      if ($MD->{'MetaDataType'} eq "1.3.6.1.4.1.311.10.11.105")
      {
        # It's structured the same way as the METAEKUS, just with
	# different OIDs (always the same)
	my $Thing = $asn_ekus->decode($MD->{'MetaDataValue'}->{'RealContent'});
	foreach my $oid (@$Thing) {
	  $oid = friendlynameOID($oid);
	}
	$MD->{'PropID105'} = $Thing;
	delete $MD->{'MetaDataType'};
	delete $MD->{'MetaDataValue'};
      }

      # OID_CERT_PROP_ID_PREFIX_122
      # May be EKU disallow
      if ($MD->{'MetaDataType'} eq "1.3.6.1.4.1.311.10.11.122")
      {
        # It's structured the same way as the METAEKUS
	my $Thing = $asn_ekus->decode($MD->{'MetaDataValue'}->{'RealContent'});
	foreach my $oid (@$Thing) {
	  $oid = friendlynameOID($oid);
	}
	$MD->{'PropID122'} = $Thing;
	delete $MD->{'MetaDataType'};
	delete $MD->{'MetaDataValue'};
      }
    }
  }

  # Pretty print the result
  printctl($ctl);
}

