#!/usr/bin/env python3

import logging
import os
import re
from typing import Optional

from androguard.core.bytecodes.dvm import EncodedMethod

import motan.categories as categories
from motan import vulnerability as vuln
from motan.analysis import AndroidAnalysis


class InsecureConnection(categories.ICodeVulnerability):
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

            # Url patterns to exclude from the results.
            exclude_start_with = (
                "http://localhost",
                "http://192.168",
                "http://example.com",
                "http://www.example.com",
                "http://hostname",
                "http://www.w3.org",
                "http://xml.org",
                "http://java.sun.com",
                "http://books.google",
                "http://plus.google",
                "http://play.google",
                "http://google",
                "http://goo.gl",
                "http://www.google",
                "http://apache.org/xml",
                "http://www.apache.org/xml",
                "http://www.altova.com/language_select.html",
                "http://www.rsasecurity.com/rsalabs/otps/schemas",
                "http://zxing.appspot.com",
                "http://schemas.android.com",
                "http://*/*",
                "http://xmlpull.org",
                "http://schemas.xmlsoap.org",
                "http://ns.adobe.com",
                "http://purl.org",
                "http://iptc.org",
                "http://www.aiim.org",
                "http://www.npes.org",
                "http://www.xfa.org",
                "http://uri.etsi.org",
                "http://ns.useplus.org",
                "http://javax.xml.XMLConstants",
                "http://mfpredirecturi",
                "http://[",
            )
            exclude_end_with = (
                "/namespace",
                "/namespaces",
                "-dtd",
                ".dtd",
                "-handler",
                "-instance",
            )

            # Check all the places where insecure plain http links are used as constant
            # strings, and put the caller method in the list with the vulnerabilities
            # if all the conditions are met.
            for string, string_analysis in dx.get_strings_analysis().items():
                # The list of methods that contain the vulnerability. The key is the
                # full method signature where the vulnerable code was found, while the
                # value is the signature of the vulnerable API/other info about the
                # vulnerability.
                vulnerable_methods = {}

                url = re.search(r"http://\S+", string)
                url = url.group(0) if url else None
                if (
                    url
                    and not url.lower().startswith(exclude_start_with)
                    and not url.lower().endswith(exclude_end_with)
                ):
                    for caller in string_analysis.get_xref_from():
                        caller_method: EncodedMethod = caller[1]

                        # Ignore excluded methods (if any).
                        if analysis_info.ignore_libs:
                            if any(
                                caller_method.get_class_name().startswith(prefix)
                                for prefix in analysis_info.ignored_classes_prefixes
                            ):
                                continue

                        vulnerable_methods[
                            f"{caller_method.get_class_name()}->"
                            f"{caller_method.get_name()}{caller_method.get_descriptor()}"
                        ] = url

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
