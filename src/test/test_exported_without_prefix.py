#!/usr/bin/env python3

import os

from motan.analysis import AndroidAnalysis
from motan.android_vulnerabilities.exported_without_prefix import ExportedWithoutPrefix


class TestExportedWithoutPrefix(object):
    def test_existing_vulnerability(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "test_resources",
            "motan-test-app.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        vulnerability = ExportedWithoutPrefix().check_vulnerability(analysis)

        assert vulnerability.id == "ExportedWithoutPrefix"
        assert len(vulnerability.code) == 1
