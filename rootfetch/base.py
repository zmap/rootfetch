# -*- coding: utf-8 -*-

import os
import tempfile


class RootStoreFetcher(object):
    """Abstract base class for fetching a root store"""

    def __init__(self, *args, **kwargs):
        pass

    def setup(self, *args, **kwargs):
        pass

    def fetch(self, output):
        raise NotImplementedError

    @staticmethod
    def _make_temp_path(suffix):
        """Returns a path to a not-yet-created temporary file. The path points
        inside a newly-created temporary folder."""
        return os.path.join(RootStoreFetcher._make_temp_directory(''), suffix)

    @staticmethod
    def _make_temp_directory(suffix):
        return tempfile.mkdtemp(suffix=suffix)
