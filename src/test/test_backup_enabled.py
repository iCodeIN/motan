#!/usr/bin/env python3

import os

from motan.analysis import AndroidAnalysis
from motan.android_vulnerabilities.backup_enabled import BackupEnabled


class TestBackupEnabled(object):
    def test_existing_vulnerability(self):
        apk_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "test_resources",
            "motan-test-app.apk",
        )

        analysis = AndroidAnalysis(apk_path, ignore_libs=True)
        vulnerability = BackupEnabled().check_vulnerability(analysis)

        assert vulnerability.id == "BackupEnabled"
        assert len(vulnerability.code) == 1
