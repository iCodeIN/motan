#!/usr/bin/env python3

import logging
import os
from typing import Optional

import lief

import motan.categories as categories
from motan import vulnerability as vuln
from motan.analysis import IOSAnalysis


class CodeSignatureMissing(categories.ICodeVulnerability):
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

            try:
                if analysis_info.macho_object.code_signature.data_size > 0:
                    return None
                else:
                    return details
            except lief.not_found:
                # code_signature is not found --> app not signed
                return details

        except Exception as e:
            self.logger.error(
                f"Error during '{self.__class__.__name__}' vulnerability check: {e}"
            )
            raise

        finally:
            analysis_info.checked_vulnerabilities.append(self.__class__.__name__)