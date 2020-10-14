#!/usr/bin/env python3

import itertools
import logging
import os
from typing import Optional

from androguard.core.bytecodes.dvm import EncodedMethod

import motan.categories as categories
from motan import vulnerability as vuln
from motan.analysis import AndroidAnalysis
from motan.util import is_class_implementing_interfaces, RegisterAnalyzer


class InsecureHostnameVerifier(categories.ICodeVulnerability):
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

            # Look for the implementation(s) of the HostnameVerifier interface
            # (https://developer.android.com/reference/javax/net/ssl/HostnameVerifier)
            # and check if the return value is hardcoded to true (1).
            interface_implementations = []
            classes = dx.get_internal_classes()
            for clazz in classes:
                if is_class_implementing_interfaces(
                    clazz.get_vm_class(), ["Ljavax/net/ssl/HostnameVerifier;"]
                ):
                    for method in clazz.get_vm_class().get_methods():
                        if (method.get_name() == "verify") and (
                            method.get_descriptor()
                            == "(Ljava/lang/String; Ljavax/net/ssl/SSLSession;)Z"
                        ):
                            register_analyzer = RegisterAnalyzer(
                                method.get_instructions()
                            )
                            result = (
                                register_analyzer.get_last_instruction_return_value()
                            )

                            # 1 means all hostnames are verified (the vulnerability is
                            # present).
                            if result == 1:
                                interface_implementations.append(
                                    method.get_class_name()
                                )

            # No HostnameVerifier interface implementation was not found, there is no
            # reason to continue checking this vulnerability.
            if not interface_implementations:
                return None

            # The target methods are the ones that set the HostnameVerifier.
            target_methods = [
                dx.get_method_analysis_by_name(
                    "Ljavax/net/ssl/HttpsURLConnection;",
                    "setHostnameVerifier",
                    "(Ljavax/net/ssl/HostnameVerifier;)V",
                ),
                dx.get_method_analysis_by_name(
                    "Ljavax/net/ssl/HttpsURLConnection;",
                    "setDefaultHostnameVerifier",
                    "(Ljavax/net/ssl/HostnameVerifier;)V",
                ),
            ]

            # No target methods were found, there is no reason to continue checking
            # this vulnerability.
            if not target_methods or not any(target_methods):
                return None

            # The list of methods that contain the vulnerability. The key is the full
            # method signature where the vulnerable code was found, while the value is
            # the signature of the vulnerable API/other info about the vulnerability.
            vulnerable_methods = {}

            for caller in itertools.chain.from_iterable(
                [
                    target_method.get_xref_from()
                    for target_method in target_methods
                    if target_method
                ]
            ):
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

                target_instr = caller_method.get_instruction(target_method_pos)

                self.logger.debug("")
                self.logger.debug(
                    f"This is the target method invocation "
                    f"(found in class '{caller_method.get_class_name()}'): "
                    f"{target_instr.get_name()} {target_instr.get_output()}"
                )

                interesting_register = f"v{target_instr.get_operands()[-2][1]}"
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
                    hostname_verifier_class = result.get_result()[-2].get_class_name()
                except Exception:
                    hostname_verifier_class = None

                self.logger.debug(
                    f"{interesting_register} value is {hostname_verifier_class}"
                )

                # Check if hostname_verifier_class is in the list of classes that
                # implement HostnameVerifier interface with a hardcoded return value.
                if hostname_verifier_class in interface_implementations:
                    vulnerable_methods[
                        f"{caller_method.get_class_name()}->"
                        f"{caller_method.get_name()}{caller_method.get_descriptor()}"
                    ] = (
                        f"{hostname_verifier_class}->"
                        f"verify(Ljava/lang/String; Ljavax/net/ssl/SSLSession;)Z"
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
