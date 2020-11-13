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


class BannedAPI(categories.ICodeVulnerability):
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        super().__init__()

    def check_vulnerability(
        self, analysis_info: IOSAnalysis
    ) -> Optional[vuln.VulnerabilityDetails]:
        self.logger.debug(f"Checking '{self.__class__.__name__}' vulnerability")
        
        try:
            bin_path = Path(analysis_info.bin_path)
            macho_object = lief.parse(bin_path.as_posix())
            details = vuln.get_vulnerability_details(
                os.path.dirname(os.path.realpath(__file__)), analysis_info.language
            )
            details.id = self.__class__.__name__

            # TODO to complete
            vulnerability_found = False
            symbols = "\n".join([x.name for x in macho_object.symbols])

            # add configuration file where the plugin read the name of API
            banned = re.findall(
                '_alloca|_gets|_memcpy|_printf|_scanf|'
                '_sprintf|_sscanf|_strcat|'
                'StrCat|_strcpy|StrCpy|_strlen|StrLen|'
                '_strncat|StrNCat|_strncpy|'
                'StrNCpy|_strtok|_swprintf|_vsnprintf|'
                '_vsprintf|_vswprintf|_wcscat|_wcscpy|'
                '_wcslen|_wcsncat|_wcsncpy|_wcstok|_wmemcpy|'
                '_fopen|_chmod|_chown|_stat|_mktemp', symbols)
            banned_api = list(set(banned))

            if len(banned_api) > 0:
                vulnerability_found = True
                details.code.extend(", ".join(banned_api))

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