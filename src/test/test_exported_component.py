#!/usr/bin/env python3

import os

from motan.analysis import AndroidAnalysis
from motan.android_vulnerabilities.exported_component import ExportedComponent


class TestExportedComponent(object):
    def test_existing_vulnerability(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "test_resources",
            "InsecureBankv2",
            "InsecureBankv2.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        vulnerability = ExportedComponent().check_vulnerability(analysis)

        assert vulnerability.id == ExportedComponent.__name__
        assert len(vulnerability.code) == 6
