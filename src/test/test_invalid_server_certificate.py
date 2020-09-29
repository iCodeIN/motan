#!/usr/bin/env python3

import os

from motan.analysis import AndroidAnalysis
from motan.android_vulnerabilities.invalid_server_certificate import (
    InvalidServerCertificate,
)


class TestInvalidServerCertificate(object):
    def test_existing_vulnerability(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "test_resources",
            "android-app-vulnerability-benchmarks",
            "CheckValidity-InformationExposure-Lean-benign.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        vulnerability = InvalidServerCertificate().check_vulnerability(analysis)

        assert vulnerability.id == "InvalidServerCertificate"
        assert len(vulnerability.code) == 1

    def test_existing_vulnerability2(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "test_resources",
            "android-app-vulnerability-benchmarks",
            "InvalidCertificateAuthority-MITM-Lean-benign.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        vulnerability = InvalidServerCertificate().check_vulnerability(analysis)

        assert vulnerability.id == "InvalidServerCertificate"
        assert len(vulnerability.code) == 1
