#!/usr/bin/env python3

import os

from motan.analysis import AndroidAnalysis
from motan.android_vulnerabilities.webview_ignore_ssl_error import WebViewIgnoreSslError


class TestWebViewIgnoreSslError(object):
    def test_existing_vulnerability(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "test_resources",
            "android-app-vulnerability-benchmarks",
            "WebViewIgnoreSSLWarning-MITM-Lean-benign.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        vulnerability = WebViewIgnoreSslError().check_vulnerability(analysis)

        assert vulnerability.id == WebViewIgnoreSslError.__name__
        assert len(vulnerability.code) == 1
