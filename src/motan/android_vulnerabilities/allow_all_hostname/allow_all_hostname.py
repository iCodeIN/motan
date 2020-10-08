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


class AllowAllHostname(categories.ICodeVulnerability):
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

            # The target method is the one setting the HostnameVerifier (however this
            # method is deprecated since Android API 22):
            # https://developer.android.com/reference/org/apache/http/conn/ssl/SSLSocketFactory
            target_method: MethodClassAnalysis = dx.get_method_analysis_by_name(
                "Lorg/apache/http/conn/ssl/SSLSocketFactory;",
                "setHostnameVerifier",
                "(Lorg/apache/http/conn/ssl/X509HostnameVerifier;)V",
            )

            # The target method was not found, there is no reason to continue checking
            # this vulnerability.
            if not target_method:
                return None

            # The list of methods that contain the vulnerability. The key is the full
            # method signature where the vulnerable code was found, while the value is
            # the signature of the vulnerable API/other info about the vulnerability.
            vulnerable_methods = {}

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
                    "Going backwards in the list of instructions to check the "
                    "register's value..."
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

                try:
                    if result.is_class_container(-2):
                        hostname_verifier_value = result.get_result()[
                            -2
                        ].get_class_name()
                    else:
                        hostname_verifier_value = result.get_result()[
                            -2
                        ].get_full_name()
                except Exception:
                    hostname_verifier_value = None

                self.logger.debug(
                    f"{interesting_register} value is {hostname_verifier_value}"
                )

                # Check if hostname_verifier_value is vulnerable.
                if hostname_verifier_value in [
                    "Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;",
                    "Lorg/apache/http/conn/ssl/SSLSocketFactory;->"
                    "ALLOW_ALL_HOSTNAME_VERIFIER "
                    "Lorg/apache/http/conn/ssl/X509HostnameVerifier;",
                ]:
                    vulnerable_methods[
                        f"{caller_method.get_class_name()}->"
                        f"{caller_method.get_name()}{caller_method.get_descriptor()}"
                    ] = (
                        "Lorg/apache/http/conn/ssl/SSLSocketFactory;->"
                        "setHostnameVerifier"
                        "(Lorg/apache/http/conn/ssl/X509HostnameVerifier;)V"
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
