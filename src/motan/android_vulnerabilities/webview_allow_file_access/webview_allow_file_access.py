#!/usr/bin/env python3

import logging
import os
from typing import Optional, List

from androguard.core.analysis.analysis import MethodAnalysis
from androguard.core.bytecodes.dvm import EncodedMethod

import motan.categories as categories
from motan import vulnerability as vuln
from motan.analysis import AndroidAnalysis
from motan.taint_analysis import TaintAnalysis


class CustomTaintAnalysis(TaintAnalysis):
    def vulnerable_path_found_callback(
        self,
        full_path: List[MethodAnalysis],
        caller: MethodAnalysis = None,
        target: MethodAnalysis = None,
        last_invocation_params: list = None,
    ):
        if (
            caller
            and target
            and last_invocation_params
            and len(last_invocation_params) > 1
        ):
            # 1 means that the flag is enabled.
            if last_invocation_params[1] == 1:
                # The key is the full method signature where the vulnerable code was
                # found, while the value is a tuple with the signature of the vulnerable
                # target method and the full path leading to the vulnerability.
                self.vulnerabilities[
                    f"{caller.class_name}->{caller.name}{caller.descriptor}"
                ] = (
                    f"{target.class_name}->{target.name}{target.descriptor}",
                    " --> ".join(
                        f"{p.class_name}->{p.name}{p.descriptor}" for p in full_path
                    ),
                )


class WebViewAllowFileAccess(categories.ICodeVulnerability):
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

            # The target method is the WebView API that enables file access
            # https://developer.android.com/reference/android/webkit/WebSettings#setAllowFileAccess(boolean)
            target_method: MethodAnalysis = dx.get_method_analysis_by_name(
                "Landroid/webkit/WebSettings;", "setAllowFileAccess", "(Z)V"
            )

            # The list of methods that contain the vulnerability. The key is the
            # full method signature where the vulnerable code was found, while the
            # value is a tuple with the signature of the vulnerable API/other info
            # about the vulnerability and the full path leading to the
            # vulnerability.
            vulnerable_methods = {}

            if not target_method:
                # The target method was not found. Before Android R (API 30), file
                # access within WebView is enabled by default, so we have to check
                # if WebView is used.
                if int(analysis_info.get_apk_analysis().get_target_sdk_version()) < 30:
                    class_analysis = dx.get_class_analysis(
                        "Landroid/webkit/WebSettings;"
                    )
                    # The target class was not found, there is no reason to continue
                    # checking this vulnerability.
                    if not class_analysis:
                        return None
                    for caller in class_analysis.get_xref_from():
                        for m in caller.get_methods():
                            m = m.get_method()

                            # Ignore excluded methods (if any).
                            if analysis_info.ignore_libs:
                                if any(
                                    m.get_class_name().startswith(prefix)
                                    for prefix in analysis_info.ignored_classes_prefixes
                                ):
                                    continue

                            if isinstance(m, EncodedMethod):
                                for i in m.get_instructions():
                                    if i.get_output().endswith(
                                        "Landroid/webkit/WebView;->"
                                        "getSettings()Landroid/webkit/WebSettings;"
                                    ):
                                        # WebSettings was found.

                                        taint_analysis = CustomTaintAnalysis(
                                            dx.get_method(m), analysis_info
                                        )
                                        path_to_caller = (
                                            taint_analysis.get_paths_to_target_method()[
                                                0
                                            ]
                                        )

                                        vulnerable_methods[
                                            f"{m.get_class_name()}->"
                                            f"{m.get_name()}{m.get_descriptor()}"
                                        ] = (
                                            "Landroid/webkit/WebSettings;",
                                            " --> ".join(
                                                f"{p.class_name}->"
                                                f"{p.name}{p.descriptor}"
                                                for p in path_to_caller
                                            ),
                                        )

                    for key, value in vulnerable_methods.items():
                        vulnerability_found = True
                        details.code.append(
                            vuln.VulnerableCode(value[0], key, value[1])
                        )
            else:
                # Check all the places where the target method is used, and put the
                # caller method in the list with the vulnerabilities if all the
                # conditions are met.
                taint_analysis = CustomTaintAnalysis(target_method, analysis_info)

                code_vulnerabilities = taint_analysis.find_code_vulnerabilities()

                if code_vulnerabilities:
                    vulnerability_found = True
                    details.code.extend(code_vulnerabilities)

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
