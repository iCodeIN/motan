#!/usr/bin/env python3

import os

from motan.analysis import AndroidAnalysis
from motan.android_vulnerabilities.crypto_ecb_cipher import CryptoEcbCipher


class TestCryptoEcbCipher(object):
    def test_existing_vulnerability(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "test_resources",
            "android-app-vulnerability-benchmarks",
            "BlockCipher-ECB-InformationExposure-Lean-benign.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        vulnerability = CryptoEcbCipher().check_vulnerability(analysis)

        assert vulnerability.id == "CryptoEcbCipher"
        assert len(vulnerability.code) == 2
