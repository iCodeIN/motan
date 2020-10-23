#!/usr/bin/env python3

import logging
import os
from typing import Optional

from androguard.core.analysis.analysis import MethodAnalysis
from androguard.core.bytecodes.dvm import EncodedMethod

import motan.categories as categories
from motan import vulnerability as vuln
from motan.analysis import AndroidAnalysis


class InsecureSocketFactory(categories.ICodeVulnerability):
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

            dx = analysis_info.get_dex_analysis()

            # The target method is the insecure socket.
            target_method: MethodAnalysis = dx.get_method_analysis_by_name(
                "Landroid/net/SSLCertificateSocketFactory;",
                "getInsecure",
                "(I Landroid/net/SSLSessionCache;)Ljavax/net/ssl/SSLSocketFactory;",
            )

            # The target method was not found, there is no reason to continue checking
            # this vulnerability.
            if not target_method:
                return None

            # The list of methods that contain the vulnerability. The key is the full
            # method signature where the vulnerable code was found, while the value is
            # the signature of the vulnerable API/other info about the vulnerability.
            vulnerable_methods = {}

            # Check all the places where the target method is used, and put the caller
            # method in the list with the vulnerabilities.
            for caller in target_method.get_xref_from():
                caller_method: EncodedMethod = caller[1].get_method()

                # Ignore excluded methods (if any).
                if analysis_info.ignore_libs and any(
                    caller_method.get_class_name().startswith(prefix)
                    for prefix in analysis_info.ignored_classes_prefixes
                ):
                    continue

                vulnerable_methods[
                    f"{caller_method.get_class_name()}->"
                    f"{caller_method.get_name()}{caller_method.get_descriptor()}"
                ] = (
                    f"{target_method.get_method().get_class_name()}->"
                    f"{target_method.get_method().get_name()}"
                    f"{target_method.get_method().get_descriptor()}"
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
