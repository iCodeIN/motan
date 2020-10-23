#!/usr/bin/env python3

import os

from motan.analysis import AndroidAnalysis
from motan.android_vulnerabilities.crypto_constant_salt import CryptoConstantSalt


class TestCryptoConstantSalt(object):
    def test_existing_vulnerability(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "test_resources",
            "android-app-vulnerability-benchmarks",
            "PBE-ConstantSalt-InformationExposure-Lean-benign.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        vulnerability = CryptoConstantSalt().check_vulnerability(analysis)

        assert vulnerability.id == "CryptoConstantSalt"
        assert len(vulnerability.code) == 1
