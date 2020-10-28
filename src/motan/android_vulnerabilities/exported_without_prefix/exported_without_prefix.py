#!/usr/bin/env python3

import logging
import os
from typing import Optional

import motan.categories as categories
from motan import vulnerability as vuln
from motan.analysis import AndroidAnalysis


class ExportedWithoutPrefix(categories.IManifestVulnerability):
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        super().__init__()

    # noinspection PyProtectedMember
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

            apk = analysis_info.get_apk_analysis()

            for tag in [
                "activity",
                "activity-alias",
                "service",
                "receiver",
                "provider",
            ]:
                for item in apk.find_tags(tag):
                    name = item.get(apk._ns("name"), "")
                    exported = item.get("exported")

                    if name.strip() and exported:
                        vulnerability_found = True
                        details.code.append(
                            vuln.VulnerableCode(
                                f'exported {tag} "{name}" without "android:" prefix',
                                "AndroidManifest.xml",
                                "AndroidManifest.xml",
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
