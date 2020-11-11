#!/usr/bin/env python3

import logging
import os
from abc import ABC
from typing import Optional, List

from androguard.core.analysis.analysis import Analysis as AndroguardAnalysis
from androguard.core.bytecodes.apk import APK
from androguard.misc import AnalyzeAPK

from motan import util


class BaseAnalysis(ABC):
    """
    This base class holds the details and the internal state of a vulnerability analysis
    for a mobile application. When analyzing a new application, an instance of a child
    of this class has to be instantiated and passed to all the code checking for
    vulnerabilities (in sequence).
    """

    pass


class AndroidAnalysis(BaseAnalysis):
    def __init__(self, apk_path: str, language: str = "en", ignore_libs: bool = False):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

        self.apk_path: str = apk_path
        self.language: str = language
        self.ignore_libs: bool = ignore_libs

        # The list of class prefixes to ignore during the vulnerability analysis
        # (to be used when ignore_libs parameter is True).
        self.ignored_classes_prefixes: List[str] = []

        # The list of vulnerabilities already checked for this application.
        self.checked_vulnerabilities: List[str] = []

        self._apk_analysis: Optional[APK] = None
        self._dex_analysis: Optional[AndroguardAnalysis] = None

        # Check if the apk file to analyze is a valid file.
        if not os.path.isfile(self.apk_path):
            self.logger.error(f"Unable to find file '{self.apk_path}'")
            raise FileNotFoundError(f"Unable to find file '{self.apk_path}'")

        if self.ignore_libs:
            self.ignored_classes_prefixes = list(
                map(
                    lambda x: f"L{x}",  # Class names start with L.
                    util.get_libs_to_ignore(),
                )
            )

        self.logger.info(f"Analyzing Android application '{apk_path}'")
        self.perform_androguard_analysis()

    def perform_androguard_analysis(self) -> None:
        self._apk_analysis, _, self._dex_analysis = AnalyzeAPK(self.apk_path)

    def get_apk_analysis(self) -> APK:
        if not self._apk_analysis or not self._dex_analysis:
            self.perform_androguard_analysis()

        return self._apk_analysis

    def get_dex_analysis(self) -> AndroguardAnalysis:
        if not self._apk_analysis or not self._dex_analysis:
            self.perform_androguard_analysis()

        return self._dex_analysis


class IOSAnalysis(BaseAnalysis):
    def __init__(self, ipa_path: str, language: str = "en"):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

        self.ipa_path: str = ipa_path
        self.language: str = language

        dir_binary_extraction = self.ipa_path.rsplit(".", 1)[0] + "_binary"

        self.bin_path = util.unpacking_ios_app(ipa_path, dir_binary_extraction)
        # The list of vulnerabilities already checked for this application.
        self.checked_vulnerabilities: List[str] = []

        self.logger.info(f"Analyzing iOS application '{ipa_path}'")

