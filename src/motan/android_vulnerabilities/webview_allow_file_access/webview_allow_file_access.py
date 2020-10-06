#!/usr/bin/env python3

import logging
import os
from typing import Optional

from androguard.core.analysis.analysis import MethodClassAnalysis
from androguard.core.bytecodes.dvm import EncodedMethod

import motan.categories as categories
from motan import vulnerability as vuln
from motan.analysis import AndroidAnalysis
from motan.util import RegisterAnalyzer


class WebViewAllowFileAccess(categories.ICodeVulnerability):
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

            # The target method is the WebView API that enables file access
            # https://developer.android.com/reference/android/webkit/WebSettings#setAllowFileAccess(boolean)
            target_method: MethodClassAnalysis = dx.get_method_analysis_by_name(
                "Landroid/webkit/WebSettings;", "setAllowFileAccess", "(Z)V"
            )

            # The list of methods that contain the vulnerability. The key is the full
            # method signature where the vulnerable code was found, while the value is
            # the signature of the vulnerable API/other info about the vulnerability.
            vulnerable_methods = {}

            if not target_method:
                # The target method was not found. Before Android R (API 30), file
                # access within WebView is enabled by default, so we have to check
                # if WebView is used.
                if int(analysis_info.get_apk_analysis().get_target_sdk_version()) < 30:
                    for caller in dx.get_class_analysis(
                        "Landroid/webkit/WebSettings;"
                    ).get_xref_from():
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
                                        vulnerable_methods[
                                            f"{m.get_class_name()}->"
                                            f"{m.get_name()}{m.get_descriptor()}"
                                        ] = "Landroid/webkit/WebSettings;"
            else:
                # Check all the places where the target method is used, and put the
                # caller method in the list with the vulnerabilities if all the
                # conditions are met.
                for caller in target_method.get_xref_from():
                    caller_method: EncodedMethod = caller[1]
                    offset_in_caller_code: int = caller[2]

                    # Ignore excluded methods (if any).
                    if analysis_info.ignore_libs:
                        if any(
                            caller_method.get_class_name().startswith(prefix)
                            for prefix in analysis_info.ignored_classes_prefixes
                        ):
                            continue

                    # Get the position (of the target_method invocation) from the offset
                    # value.
                    target_method_pos = (
                        caller_method.get_code()
                        .get_bc()
                        .off_to_pos(offset_in_caller_code)
                    )

                    self.logger.debug("")
                    self.logger.debug(
                        f"This is the target method invocation "
                        f"(found in class '{caller_method.get_class_name()}'): "
                        f"{caller_method.get_instruction(target_method_pos).get_name()} "
                        f"{caller_method.get_instruction(target_method_pos).get_output()}"
                    )

                    interesting_register = (
                        f"v{caller_method.get_instruction(target_method_pos).D}"
                    )
                    self.logger.debug(
                        f"Register with interesting param: {interesting_register}"
                    )
                    self.logger.debug(
                        "Going backwards in the list of instructions to check if "
                        "the register's value is constant..."
                    )

                    off = 0
                    for n, i in enumerate(caller_method.get_instructions()):
                        self.logger.debug(
                            f"{n:8d} (0x{off:08x}) {i.get_name():30} {i.get_output()}"
                        )

                        off += i.get_length()
                        if off > offset_in_caller_code:
                            break

                    register_analyzer = RegisterAnalyzer(
                        caller_method.get_instructions(), offset_in_caller_code
                    )
                    result = RegisterAnalyzer.Result(
                        register_analyzer.get_last_instruction_register_to_value_mapping()
                    )

                    self.logger.debug(
                        f"{interesting_register} value is {result.get_result()[-2]}"
                    )

                    # 1 means that the flag is enabled.
                    if result.get_result()[-2] == 1:
                        vulnerable_methods[
                            f"{caller_method.get_class_name()}->"
                            f"{caller_method.get_name()}"
                            f"{caller_method.get_descriptor()}"
                        ] = "Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V"

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
