#!/usr/bin/env python3

import logging
import os
from typing import Optional

import motan.categories as categories
from motan import vulnerability as vuln
from motan.analysis import AndroidAnalysis


class BackupEnabled(categories.IManifestVulnerability):
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        super().__init__()

    def check_vulnerability(
        self, analysis_info: AndroidAnalysis
    ) -> Optional[vuln.VulnerabilityDetails]:
        self.logger.debug(f"Checking '{self.__class__.__name__}' vulnerability")

        try:
            vulnerability_found = False

            # Load the vulnerability details.
            details = vuln.get_vulnerability_details(
                os.path.dirname(os.path.realpath(__file__)), analysis_info.language
            )
            details.id = self.__class__.__name__

            allow_backup = analysis_info.get_apk_analysis().get_attribute_value(
                "application", "allowBackup"
            )
            if allow_backup is None:
                vulnerability_found = True
                details.code.append(
                    vuln.VulnerableCode(
                        "allowBackup not set (true by default)", "AndroidManifest.xml"
                    )
                )
            elif allow_backup and allow_backup.lower() == "true":
                vulnerability_found = True
                details.code.append(
                    vuln.VulnerableCode(
                        'android:allowBackup="true"', "AndroidManifest.xml"
                    )
                )

            if vulnerability_found:
                return details
            else:
                return None

        except Exception as e:
            self.logger.error(
                f"Error during '{self.__class__.__name__}' vulnerability check: {e}"
            )
            raise

        finally:
            analysis_info.checked_vulnerabilities.append(self.__class__.__name__)
