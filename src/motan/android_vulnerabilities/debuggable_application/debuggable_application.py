#!/usr/bin/env python3

import logging

import motan.categories as categories
from motan.analysis import AndroidAnalysis


class DebuggableApplication(categories.IManifestVulnerability):
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        super().__init__()

    def check_vulnerability(self, analysis_info: AndroidAnalysis):
        self.logger.info(f"Checking '{self.__class__.__name__}' vulnerability")

        try:
            debuggable = analysis_info.get_apk_analysis().get_attribute_value(
                "application", "debuggable"
            )
            if debuggable and debuggable.lower() == "true":
                # TODO
                self.logger.info("The application is debuggable")
        except Exception as e:
            self.logger.error(
                f"Error during '{self.__class__.__name__}' vulnerability check: {e}"
            )
            raise

        finally:
            analysis_info.checked_vulnerabilities.append(self.__class__.__name__)
