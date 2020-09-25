#!/usr/bin/env python3

import logging
import os
from typing import Optional

from androguard.core.analysis.analysis import MethodClassAnalysis
from androguard.core.bytecodes.dvm import EncodedMethod

import motan.categories as categories
from motan import vulnerability as vuln
from motan.analysis import AndroidAnalysis


class ExternalStorage(categories.ICodeVulnerability):
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        super().__init__()

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

            # The target method is the Android API that accesses the external storage.
            target_method: MethodClassAnalysis = dx.get_method_analysis_by_name(
                "Landroid/os/Environment;",
                "getExternalStorageDirectory",
                "()Ljava/io/File;",
            )

            # The target method was not found, there is no reason to continue checking
            # this vulnerability.
            if not target_method:
                return None

            # The list of methods that contain the vulnerability. After the methods are
            # added to this list, the duplicates will be removed.
            vulnerable_methods = []

            # Check all the places where the target method is used, and put the caller
            # method in the list with the vulnerabilities.
            for caller in target_method.get_xref_from():
                caller_method: EncodedMethod = caller[1]

                # Ignore excluded methods (if any).
                if analysis_info.ignore_libs and any(
                    caller_method.get_class_name().startswith(prefix)
                    for prefix in analysis_info.ignored_classes_prefixes
                ):
                    continue

                vulnerable_methods.append(caller_method)

            # Iterate over a list with the unique vulnerable methods.
            for method in {str(m): m for m in vulnerable_methods}.values():
                vulnerability_found = True
                details.code.append(
                    vuln.VulnerableCode(
                        "Landroid/os/Environment;->"
                        "getExternalStorageDirectory()Ljava/io/File;",
                        f"{method.get_class_name()}->"
                        f"{method.get_name()}{method.get_descriptor()}",
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
