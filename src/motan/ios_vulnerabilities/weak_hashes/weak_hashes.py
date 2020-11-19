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
import re


class WeakHashes(categories.ICodeVulnerability):
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

            # TODO add configuration file where the plugin read the name of API
            weak_hashes = re.findall(
                "CC_MD2_Init|CC_MD2_Update|"
                "CC_MD2_Final|CC_MD2|MD2_Init|"
                "MD2_Update|MD2_Final|CC_MD4_Init|"
                "CC_MD4_Update|CC_MD4_Final|"
                "CC_MD4|MD4_Init|MD4_Update|"
                "MD4_Final|CC_MD5_Init|CC_MD5_Update|"
                "CC_MD5_Final|CC_MD5|MD5_Init|"
                "MD5_Update|MD5_Final|MD5Init|"
                "MD5Update|MD5Final|CC_SHA1_Init|"
                "CC_SHA1_Update|"
                "CC_SHA1_Final|CC_SHA1|SHA1_Init|"
                "SHA1_Update|SHA1_Final",
                analysis_info.macho_symbols,
            )
            weak_hashes_api = list(set(weak_hashes))
            if len(weak_hashes_api) > 0:
                vulnerability_found = True
                details.api = ", ".join(weak_hashes_api)

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
