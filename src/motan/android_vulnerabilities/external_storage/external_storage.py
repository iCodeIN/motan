#!/usr/bin/env python3

import logging

from androguard.core.analysis.analysis import MethodClassAnalysis
from androguard.core.bytecodes.dvm import EncodedMethod

import motan.categories as categories
from motan.analysis import AndroidAnalysis


class ExternalStorage(categories.ICodeVulnerability):
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        super().__init__()

    def check_vulnerability(self, analysis_info: AndroidAnalysis):
        self.logger.info(f"Checking '{self.__class__.__name__}' vulnerability")

        try:
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
                return

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
                # TODO
                self.logger.info(
                    f"External storage access found in class "
                    f"'{method.get_class_name()}', method "
                    f"'{method.get_name()}{method.get_descriptor()}'"
                )
        except Exception as e:
            self.logger.error(
                f"Error during '{self.__class__.__name__}' vulnerability check: {e}"
            )
            raise

        finally:
            analysis_info.checked_vulnerabilities.append(self.__class__.__name__)
