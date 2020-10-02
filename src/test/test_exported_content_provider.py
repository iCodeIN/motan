#!/usr/bin/env python3

import os

from motan.analysis import AndroidAnalysis
from motan.android_vulnerabilities.exported_content_provider import (
    ExportedContentProvider,
)


class TestExportedContentProvider(object):
    def test_existing_vulnerability(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "test_resources",
            "InsecureBankv2",
            "InsecureBankv2.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        vulnerability = ExportedContentProvider().check_vulnerability(analysis)

        assert vulnerability.id == "ExportedContentProvider"
        assert len(vulnerability.code) == 1
