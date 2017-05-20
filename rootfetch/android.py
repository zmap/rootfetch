# -*- coding: utf-8 -*-
import os
import sys

import semver
import sh

from rootfetch.base import RootStoreFetcher


class AndroidFetcher(RootStoreFetcher):
    """AndroidFetcher fetches the latest Android root store.

    It fetches the root store stable Android version as defined by the tags on
    the Android platform/system/ca-certificates Git repository."""

    GIT_URL = "https://android.googlesource.com/platform/system/ca-certificates"

    def fetch(self, output):
        clone_dir = self._make_temp_directory("rootfetch-android-git")
        sh.git.clone(self.GIT_URL, clone_dir)
        tags = set()
        for tag in sh.git.tag(_cwd=clone_dir, _iter=True):
            tags.add(tag.strip())
        sh.git.checkout(self._latest_stable_tag(tags), _cwd=clone_dir)
        root_dir = os.path.join(clone_dir, "files")
        for cert_path in sh.find(root_dir, "-type", "f", _iter=True):
            cert_path = cert_path.strip()
            with open(cert_path) as fd:
                pem_parts = list()
                for line in fd:
                    pem_parts.append(line)
                    if line.startswith("-----END CERTIFICATE-----"):
                        break
                output.write(''.join(pem_parts))
        output.flush()

    @staticmethod
    def _latest_stable_tag(tags):
        version_revs = dict()
        for tag in tags:
            parts = tag.split('-')
            if len(parts) != 2:
                continue
            if parts[0] != 'android':
                continue
            full_version = parts[1]
            version, rrev = full_version.split('_')
            rev = int(rrev[1:])
            if version not in version_revs:
                version_revs[version] = list()
            version_revs[version].append(rev)
        max_version = "0.0.0"
        for version in version_revs.iterkeys():
            max_version = semver.max_ver(max_version, version)
        max_rev = 0
        for rev in version_revs[max_version]:
            max_rev = max(max_rev, rev)
        return ''.join(["android-", max_version, "_r", str(max_rev)])


if __name__ == "__main__":
    a = AndroidFetcher()
    a.setup()
    a.fetch(sys.stdout)
