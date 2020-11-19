#!/usr/bin/env python3

import logging
from typing import Optional, List
import motan.categories as categories
from motan import vulnerability as vuln
from motan.analysis import IOSAnalysis
import subprocess
import os
from pathlib import Path
import lief


class NoForwardSecrecyPlist(categories.ICodeVulnerability):
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        super().__init__()

    def check_vulnerability(
        self, analysis_info: IOSAnalysis
    ) -> Optional[vuln.VulnerabilityDetails]:
        self.logger.debug(f"Checking '{self.__class__.__name__}' vulnerability")

        try:
            details = vuln.get_vulnerability_details(
                os.path.dirname(os.path.realpath(__file__)), analysis_info.language
            )
            details.id = self.__class__.__name__
            vulnerability_found = False
            if "NSAppTransportSecurity" in analysis_info.plist_readable:
                ns_app_trans_dic = analysis_info.plist_readable[
                    "NSAppTransportSecurity"
                ]
                for key in ns_app_trans_dic["NSExceptionDomains"]:
                    if (
                        "NSExceptionRequiresForwardSecrecy"
                        in ns_app_trans_dic["NSExceptionDomains"][key]
                        and ns_app_trans_dic["NSExceptionDomains"][key][
                            "NSExceptionRequiresForwardSecrecy"
                        ]
                        is False
                    ):
                        vulnerability_found = True
                        break

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