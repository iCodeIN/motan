#!/usr/bin/env python3

import logging
import math
import os
from typing import Optional

from androguard.core.androconf import is_ascii_problem

import motan.categories as categories
from motan import vulnerability as vuln
from motan.analysis import AndroidAnalysis


class ObfuscationMissing(categories.ICodeVulnerability):
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

            # Ignore excluded classes (if any).
            if analysis_info.ignore_libs:
                all_classes = list(
                    clazz
                    for clazz in dx.get_internal_classes()
                    if not any(
                        clazz.name.startswith(prefix)
                        for prefix in analysis_info.ignored_classes_prefixes
                    )
                )
            else:
                all_classes = list(dx.get_internal_classes())

            # The lists are created from a set to avoid duplicates.
            all_fields = list(
                {
                    repr(field): field
                    for clazz in all_classes
                    for field in clazz.get_fields()
                }.values()
            )
            all_methods = list(
                {
                    repr(method): method
                    for clazz in all_classes
                    for method in clazz.get_methods()
                }.values()
            )

            # Non ascii class/field/method names (probably using DexGuard).

            non_ascii_class_names = list(
                filter(lambda x: is_ascii_problem(x.name), all_classes)
            )
            non_ascii_field_names = list(
                filter(lambda x: is_ascii_problem(x.name), all_fields)
            )
            non_ascii_method_names = list(
                filter(lambda x: is_ascii_problem(x.name + x.descriptor), all_methods)
            )

            if len(all_classes) > 0:
                non_ascii_class_percentage = (
                    100 * len(non_ascii_class_names) / len(all_classes)
                )
            else:
                non_ascii_class_percentage = 0

            if len(all_fields) > 0:
                non_ascii_field_percentage = (
                    100 * len(non_ascii_field_names) / len(all_fields)
                )
            else:
                non_ascii_field_percentage = 0

            if len(all_methods) > 0:
                non_ascii_method_percentage = (
                    100 * len(non_ascii_method_names) / len(all_methods)
                )
            else:
                non_ascii_method_percentage = 0

            # Short class/field/method names (probably using ProGuard).

            # We want to find the value "N", that represents the minimum number of chars
            # needed to write as many unique names as the number of classes (the same
            # can be applied to fields and methods).

            # If the set S has BASE elements, the number of N-tuples over S is
            # CLASSES = BASE^N. We want to find N (knowing the other elements):
            # N = log_BASE_(CLASSES)
            # log_BASE_(CLASSES) = log(CLASSES) / log(BASE)
            # (when changing logarithm base)

            # BASE = 52 (26 lowercase letters + 26 uppercase letters, by default
            # ProGuard does not use numbers)
            # CLASSES = number of classes found

            BASE = 52
            CLASSES = len(all_classes)
            FIELDS = len(all_fields)
            METHODS = len(all_methods)

            if len(all_classes) > 0:
                N_CLASSES = int(math.ceil(math.log(CLASSES, BASE)))
            else:
                N_CLASSES = 0
            if len(all_fields) > 0:
                N_FIELDS = int(math.ceil(math.log(FIELDS, BASE)))
            else:
                N_FIELDS = 0
            if len(all_methods) > 0:
                N_METHODS = int(math.ceil(math.log(METHODS, BASE)))
            else:
                N_METHODS = 0

            # Function used to get the class name from full name with package.
            # Ex: com/example/name; -> name;
            def get_only_class_name(full_class):
                tokens = full_class.name.rsplit("/", 1)
                if len(tokens) == 2:
                    return tokens[1]
                else:
                    return tokens[0]

            short_class_names = list(
                filter(
                    lambda x:
                    # N_CLASSES + 1 because dex class names end with ;
                    len(get_only_class_name(x)) <= N_CLASSES + 1,
                    all_classes,
                )
            )

            short_field_names = list(
                filter(lambda x: len(x.name) <= N_FIELDS, all_fields)
            )

            short_method_names = list(
                filter(lambda x: len(x.name) <= N_METHODS, all_methods)
            )

            if len(all_classes) > 0:
                short_class_percentage = 100 * len(short_class_names) / len(all_classes)
            else:
                short_class_percentage = 0

            if len(all_fields) > 0:
                short_field_percentage = 100 * len(short_field_names) / len(all_fields)
            else:
                short_field_percentage = 0

            if len(all_methods) > 0:
                short_method_percentage = (
                    100 * len(short_method_names) / len(all_methods)
                )
            else:
                short_method_percentage = 0

            ascii_obfuscation_rate = max(
                [
                    non_ascii_class_percentage,
                    non_ascii_field_percentage,
                    non_ascii_method_percentage,
                ]
            )
            short_name_obfuscation_rate = max(
                [
                    short_class_percentage,
                    short_field_percentage,
                    short_method_percentage,
                ]
            )

            if ascii_obfuscation_rate < 30 and short_name_obfuscation_rate < 30:
                vulnerability_found = True
                details.code.append(
                    vuln.VulnerableCode(
                        f"ASCII Obfuscation: {ascii_obfuscation_rate:.2f}% "
                        f"Renaming Obfuscation: {short_name_obfuscation_rate:.2f}%",
                        "application",
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
