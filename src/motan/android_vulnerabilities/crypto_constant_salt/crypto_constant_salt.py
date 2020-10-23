#!/usr/bin/env python3

import logging
import os
from typing import Optional, List

from androguard.core.analysis.analysis import MethodAnalysis

import motan.categories as categories
from motan import vulnerability as vuln
from motan.analysis import AndroidAnalysis
from motan.util import get_paths_to_target_method, RegisterAnalyzer


class CryptoConstantSalt(categories.ICodeVulnerability):
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        super().__init__()

    def recursive_check_path(
        self,
        path: List[MethodAnalysis],
        path_start_index: int,
        return_param_index: int,
        last_invocation_params: list,
        vulnerable_methods: dict,
        analysis_info: AndroidAnalysis,
    ):
        # At least 2 methods are needed for a vulnerability: the callee
        # (vulnerable target method) and the caller method.
        if path_start_index > len(path) - 2:
            return

        caller = path[path_start_index]
        target = path[path_start_index + 1]

        # Ignore excluded methods (if any).
        if analysis_info.ignore_libs:
            if any(
                caller.get_class_name().startswith(prefix)
                for prefix in analysis_info.ignored_classes_prefixes
            ):
                return

        register_analyzer = RegisterAnalyzer(
            caller.get_method().get_instructions(),
            apk_analysis=analysis_info.get_apk_analysis(),
            dex_analysis=analysis_info.get_dex_analysis(),
            auto=False,
        )

        self.logger.debug("")
        self.logger.debug(
            f"Analyzing code in method {caller.class_name}->"
            f"{caller.name}{caller.descriptor}"
        )

        param_registers = caller.get_method().get_information().get("params")

        if last_invocation_params and param_registers:
            self.logger.debug(
                "Last invocation passed some parameters to this method:"
            )
            # Loop in reverse order to fill the parameters starting from the
            # last one.
            for param, val in reversed(
                list(zip(reversed(param_registers), reversed(last_invocation_params)))
            ):
                self.logger.debug(f"  v{param[0]} = {val}")
                register_analyzer.initialize_register_value(param[0], val)

        off = 0
        for n, i in enumerate(caller.get_method().get_instructions()):
            self.logger.debug(
                f"{n:8d} (0x{off:08x}) {i.get_name():30} {i.get_output()}"
            )

            if i.get_output().endswith(
                f"{target.class_name}->" f"{target.name}{target.descriptor}"
            ):
                target_instr = caller.get_method().get_instruction(
                    caller.get_method().get_code().get_bc().off_to_pos(off)
                )

                self.logger.debug(
                    f"This is the interesting method invocation: "
                    f"{target_instr.get_name()} {target_instr.get_output()}"
                )

                register_analyzer.load_instructions(
                    caller.get_method().get_instructions(), off
                )
                result = RegisterAnalyzer.Result(
                    register_analyzer.get_last_instruction_register_to_value_mapping()
                )

                if result.get_result():
                    last_invocation_params = result.get_result()[:-1]
                else:
                    last_invocation_params = []

                self.logger.debug(
                    f"Register values after last instruction: "
                    f"{last_invocation_params}"
                )

                # An invocation to the next method in path was found, so continue
                # analyzing the next method.
                self.recursive_check_path(
                    path,
                    path_start_index + 1,
                    return_param_index,
                    last_invocation_params,
                    vulnerable_methods,
                    analysis_info,
                )

                # The second last method in path is the one calling the target method.
                if (
                    caller == path[-2]
                    and len(last_invocation_params) > return_param_index
                    and isinstance(last_invocation_params[return_param_index], str)
                ):
                    # The target method invocation was found, with constant parameters.
                    vulnerable_methods[
                        f"{caller.class_name}->{caller.name}{caller.descriptor}"
                    ] = (
                        f'constant salt "{last_invocation_params[return_param_index]}" '
                        "parameter passed to PBEKeySpec/PBEParameterSpec",
                        " --> ".join(
                            f"{p.class_name}->{p.name}{p.descriptor}" for p in path
                        ),
                    )

                self.logger.debug("")
                self.logger.debug(
                    f"...continue analyzing code in method "
                    f"{caller.class_name}->{caller.name}{caller.descriptor}"
                )

            off += i.get_length()

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

            # The target methods are PBEKeySpec constructors taking a salt parameter.
            target_methods_keyspec = [
                dx.get_method_analysis_by_name(
                    "Ljavax/crypto/spec/PBEKeySpec;", "<init>", "([C [B I)V"
                ),
                dx.get_method_analysis_by_name(
                    "Ljavax/crypto/spec/PBEKeySpec;", "<init>", "([C [B I I)V"
                ),
            ]

            # The target methods are PBEParameterSpec constructors.
            target_methods_parameterspec = [
                dx.get_method_analysis_by_name(
                    "Ljavax/crypto/spec/PBEParameterSpec;", "<init>", "([B I)V"
                ),
                dx.get_method_analysis_by_name(
                    "Ljavax/crypto/spec/PBEParameterSpec;",
                    "<init>",
                    "([B I Ljava/security/spec/AlgorithmParameterSpec;)V",
                ),
            ]

            # Find all the code paths leading to the target method(s).
            paths_to_check_keyspec = get_paths_to_target_method(target_methods_keyspec)
            paths_to_check_parameterspec = get_paths_to_target_method(
                target_methods_parameterspec
            )

            # No paths to the target method(s) were found, there is no reason to
            # continue checking this vulnerability.
            if not paths_to_check_keyspec and not paths_to_check_parameterspec:
                return None

            # The list of methods that contain the vulnerability. The key is the full
            # method signature where the vulnerable code was found, while the value is
            # the signature of the vulnerable API/other info about the vulnerability.
            vulnerable_methods = {}

            # Check every path leading to a vulnerable method invocation.
            for path in paths_to_check_keyspec:
                self.recursive_check_path(
                    path, 0, 2, [], vulnerable_methods, analysis_info
                )
            for path in paths_to_check_parameterspec:
                self.recursive_check_path(
                    path, 0, 1, [], vulnerable_methods, analysis_info
                )

            for key, value in vulnerable_methods.items():
                vulnerability_found = True
                details.code.append(vuln.VulnerableCode(value[0], key, value[1]))

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
