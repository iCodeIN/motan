#!/usr/bin/env python3

import os

from motan.analysis import AndroidAnalysis
from motan.android_vulnerabilities.base64_url import Base64Url


class TestBase64Url(object):
    def test_existing_vulnerability(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "test_resources",
            "motan-test-app.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        vulnerability = Base64Url().check_vulnerability(analysis)

        assert vulnerability.id == Base64Url.__name__
        assert len(vulnerability.code) == 1
