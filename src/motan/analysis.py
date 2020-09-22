#!/usr/bin/env python3

import logging
import os
from abc import ABC
from typing import Union, List

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
    def __init__(
        self, apk_path: str, ignore_libs: bool = False, interactive: bool = False
    ):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

        self.apk_path: str = apk_path
        self.ignore_libs: bool = ignore_libs
        self.interactive: bool = interactive

        # The list of class prefixes to ignore during the vulnerability analysis
        # (to be used when ignore_libs parameter is True).
        self.ignored_classes_prefixes: List[str] = []

        # The list of vulnerabilities already checked for this application.
        self.checked_vulnerabilities: List[str] = []

        self._apk_analysis: Union[APK, None] = None
        self._dex_analysis: Union[AndroguardAnalysis, None] = None

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
    def __init__(self, ipa_path: str, interactive: bool = False):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

        self.ipa_path: str = ipa_path
        self.interactive: bool = interactive
