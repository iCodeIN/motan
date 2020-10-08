#!/usr/bin/env python3

import base64
import logging
import os
import re
from typing import Optional

from androguard.core.bytecodes.dvm import EncodedMethod

import motan.categories as categories
from motan import vulnerability as vuln
from motan.analysis import AndroidAnalysis


class Base64Url(categories.ICodeVulnerability):
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        super().__init__()

    @staticmethod
    def is_base64(string: str) -> bool:
        return bool(re.match("[A-Za-z0-9+/]+[=]{0,2}$", string))

    def check_vulnerability(
        self, analysis_info: AndroidAnalysis
    ) -> Optional[vuln.VulnerabilityDetails]:
        self.logger.info(f"Checking '{self.__class__.__name__}' vulnerability")

        try:
            vulnerability_found = False

            # Load the vulnerability details.
            details = vuln.get_vulnerability_details(
                os.path.dirname(os.path.realpath(__file__)), analysis_info.language
            )
            details.id = self.__class__.__name__

            dx = analysis_info.get_dex_analysis()

            for string, string_analysis in dx.get_strings_analysis().items():
                # The list of methods that contain the vulnerability. The key is the
                # full method signature where the vulnerable code was found, while the
                # value is the signature of the vulnerable API/other info about the
                # vulnerability.
                vulnerable_methods = {}

                if self.is_base64(string) and len(string) >= 10:
                    try:
                        # Try to decode the base64 string. If something goes wrong or
                        # if the decoded string is not printable, skip it.
                        decoded_string = base64.b64decode(
                            string, validate=True
                        ).decode()

                        if not decoded_string.isprintable():
                            continue

                        # Keep only urls.
                        if (
                            "http://" not in decoded_string
                            and "https://" not in decoded_string
                        ):
                            continue
                    except Exception:
                        continue

                    for caller in string_analysis.get_xref_from():
                        caller_method: EncodedMethod = caller[1]

                        # Ignore excluded methods (if any).
                        if analysis_info.ignore_libs:
                            if any(
                                caller_method.get_class_name().startswith(prefix)
                                for prefix in analysis_info.ignored_classes_prefixes
                            ):
                                continue

                        vulnerable_methods[
                            f"{caller_method.get_class_name()}->"
                            f"{caller_method.get_name()}"
                            f"{caller_method.get_descriptor()}"
                        ] = (
                            f"Original string: '{string}' "
                            f"Decoded string: '{decoded_string}'"
                        )

                for key, value in vulnerable_methods.items():
                    vulnerability_found = True
                    details.code.append(vuln.VulnerableCode(value, key))

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
