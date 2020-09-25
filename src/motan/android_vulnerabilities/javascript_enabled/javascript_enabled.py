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


class JavascriptEnabled(categories.IManifestVulnerability):
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

            # The target method is the WebView API that enables JavaScript.
            target_method: MethodClassAnalysis = dx.get_method_analysis_by_name(
                "Landroid/webkit/WebSettings;", "setJavaScriptEnabled", "(Z)V"
            )

            # The target method was not found, there is no reason to continue checking
            # this vulnerability.
            if not target_method:
                return None

            # The list of methods that contain the vulnerability. After the methods are
            # added to this list, the duplicates will be removed.
            vulnerable_methods = []

            # Check all the places where the target method is used, and put the caller
            # method in the list with the vulnerabilities if all the conditions are met.
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
                    caller_method.get_code().get_bc().off_to_pos(offset_in_caller_code)
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
                    f"{interesting_register} value is {result.get_result()[1]}"
                )

                # 1 means that the flag is enabled.
                if result.get_result()[1] == 1:
                    vulnerable_methods.append(caller_method)

            # Iterate over a list with the unique vulnerable methods.
            for method in {str(m): m for m in vulnerable_methods}.values():
                vulnerability_found = True
                details.code.append(
                    vuln.VulnerableCode(
                        "Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V",
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
