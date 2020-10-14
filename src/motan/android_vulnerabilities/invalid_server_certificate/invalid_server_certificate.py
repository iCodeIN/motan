#!/usr/bin/env python3

import logging
import os
from typing import Optional

from androguard.core.bytecodes.dvm import EncodedMethod

import motan.categories as categories
from motan import vulnerability as vuln
from motan.analysis import AndroidAnalysis
from motan.util import is_class_implementing_interfaces


class InvalidServerCertificate(categories.ICodeVulnerability):
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

            # Look for the implementation(s) of the X509TrustManager interface
            # (https://developer.android.com/reference/javax/net/ssl/X509TrustManager)
            # and check if checkServerTrusted method is empty.
            interface_implementations = []
            classes = dx.get_internal_classes()
            for clazz in classes:
                if is_class_implementing_interfaces(
                    clazz.get_vm_class(), ["Ljavax/net/ssl/X509TrustManager;"]
                ):
                    for method in clazz.get_vm_class().get_methods():
                        if (method.get_name() == "checkServerTrusted") and (
                            method.get_descriptor()
                            == "([Ljava/security/cert/X509Certificate; "
                            "Ljava/lang/String;)V"
                        ):
                            # The method has only one (return) instruction, so there is
                            # no validation on the server certificates.
                            if len(list(method.get_instructions())) <= 1:
                                interface_implementations.append(
                                    method.get_class_name()
                                )

            # No X509TrustManager interface implementation was not found, there is no
            # reason to continue checking this vulnerability.
            if not interface_implementations:
                return None

            # The list of methods that contain the vulnerability. The key is the full
            # method signature where the vulnerable code was found, while the value is
            # the signature of the vulnerable API/other info about the vulnerability.
            vulnerable_methods = {}

            # Find the method(s) where the custom X509TrustManager is used.
            for clazz in interface_implementations:
                class_analysis = dx.get_class_analysis(clazz)
                if not class_analysis:
                    continue
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
                                if i.get_op_value() == 0x22:  # 0x22 = "new-instance"
                                    if i.get_string() in interface_implementations:
                                        # A new instance of the custom X509TrustManager
                                        # was found.
                                        vulnerable_methods[
                                            f"{m.get_class_name()}->"
                                            f"{m.get_name()}{m.get_descriptor()}"
                                        ] = clazz

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
