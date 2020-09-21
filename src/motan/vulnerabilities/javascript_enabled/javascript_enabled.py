#!/usr/bin/env python3

import logging

from androguard.core.analysis.analysis import MethodClassAnalysis
from androguard.core.bytecodes.dvm import EncodedMethod

import motan.categories as categories
from motan.analysis import Analysis
from motan.util import RegisterAnalyzer


class JavascriptEnabled(categories.IManifestVulnerability):
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        super().__init__()

    def check_vulnerability(self, analysis_info: Analysis):
        self.logger.info('Checking "{0}" vulnerability'.format(self.__class__.__name__))

        try:
            dx = analysis_info.get_dex_analysis()

            target_method: MethodClassAnalysis = dx.get_method_analysis_by_name(
                "Landroid/webkit/WebSettings;", "setJavaScriptEnabled", "(Z)V"
            )

            # The target method was not found, there is no reason to continue checking
            # this vulnerability.
            if not target_method:
                return

            for caller in target_method.get_xref_from():
                caller_method: EncodedMethod = caller[1]
                offset_in_caller_code: int = caller[2]

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
                    # TODO
                    self.logger.info(
                        "JavaScript is enabled in class "
                        f"'{caller_method.get_class_name()}'"
                    )
        except Exception as e:
            self.logger.error(
                f"Error during '{self.__class__.__name__}' vulnerability check: {e}"
            )
            raise

        finally:
            analysis_info.checked_vulnerabilities.append(self.__class__.__name__)
