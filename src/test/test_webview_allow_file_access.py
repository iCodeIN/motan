#!/usr/bin/env python3

import os

from motan.analysis import AndroidAnalysis
from motan.android_vulnerabilities.webview_allow_file_access import (
    WebViewAllowFileAccess,
)


class TestWebViewAllowFileAccess(object):
    def test_existing_vulnerability(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "test_resources",
            "motan-test-app.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        vulnerability = WebViewAllowFileAccess().check_vulnerability(analysis)

        assert vulnerability.id == "WebViewAllowFileAccess"
        assert len(vulnerability.code) == 1

    def test_existing_vulnerability2(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "test_resources",
            "InsecureBankv2",
            "InsecureBankv2.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        vulnerability = WebViewAllowFileAccess().check_vulnerability(analysis)

        assert vulnerability.id == "WebViewAllowFileAccess"
        assert len(vulnerability.code) == 1
