#!/usr/bin/env python3

import logging
from typing import Optional, List
import motan.categories as categories
from motan import vulnerability as vuln
from motan.analysis import IOSAnalysis
import subprocess


class PieVulnerability(categories.ICodeVulnerability):
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        super().__init__()

    def check_vulnerability(
        self, analysis_info: IOSAnalysis
    ) -> Optional[vuln.VulnerabilityDetails]:
        self.logger.debug(f"Checking '{self.__class__.__name__}' vulnerability")

        # TODO from here to implements
        otool_bin = "otool"
        bin_path = analysis_info.bin_path
        args = [otool_bin, '-hv', bin_path]
        pie_dat = subprocess.check_output(args)
        
        if b'PIE' in pie_dat:
            pie_flag = {
                'issue': 'fPIE -pie flag is Found',
                'level': "SECURE",
                'description': ('App is compiled with Position Independent '
                                'Executable (PIE) flag. This enables Address'
                                ' Space Layout Randomization (ASLR), a memory'
                                ' protection mechanism for'
                                ' exploit mitigation.'),
                'cvss': 0,
                'cwe': '',
                'owasp': '',
            }
        else:
            pie_flag = {
                'issue': 'fPIE -pie flag is not Found',
                'level': "high",
                'description': ('with Position Independent Executable (PIE) '
                                'flag. So Address Space Layout Randomization '
                                '(ASLR) is missing. ASLR is a memory '
                                'protection mechanism for '
                                'exploit mitigation.'),
                'cvss': 2,
                'cwe': 'CWE-119',
                'owasp': 'M1: Improper Platform Usage',
            } 