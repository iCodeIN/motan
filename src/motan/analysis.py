#!/usr/bin/env python3

import logging
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, List

import lief
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

    def __init__(self, language: str = "en"):
        self.language: str = language

        # The list of vulnerabilities already checked for this application.
        self.checked_vulnerabilities: List[str] = []

    @abstractmethod
    def initialize(self):
        # This method contains the initialization (one time) operations that could
        # generate errors. This method will be called once at the beginning of each
        # new analysis.
        raise NotImplementedError()

    @abstractmethod
    def finalize(self):
        # This method contains the instructions to be called after the analysis ends
        # (e.g., cleaning temporary files). This method will be called once at the end
        # of each new analysis.
        raise NotImplementedError()


class AndroidAnalysis(BaseAnalysis):
    def __init__(self, apk_path: str, language: str = "en", ignore_libs: bool = False):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        super().__init__(language)

        self.apk_path: str = apk_path
        self.ignore_libs: bool = ignore_libs

        # The list of class prefixes to ignore during the vulnerability analysis
        # (to be used when ignore_libs parameter is True).
        self.ignored_classes_prefixes: List[str] = []

        self._apk_analysis: Optional[APK] = None
        self._dex_analysis: Optional[AndroguardAnalysis] = None

    def initialize(self):
        self.logger.info(f"Analyzing Android application '{self.apk_path}'")

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

        self.perform_androguard_analysis()

    def finalize(self):
        pass

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
    def __init__(
        self,
        ipa_path: str,
        language: str = "en",
        keep_files: bool = False,
        working_dir: str = "working_dir_motan_ios",
    ):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        super().__init__(language)

        self.ipa_path: str = ipa_path
        self.keep_files: bool = keep_files

        self.working_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.realpath(__file__))), working_dir
        )
        self.dir_binary_extraction = self.working_dir
        self.bin_path = None
        self.plist_readable = None
        self.macho_object = None
        self.macho_symbols = None

    def initialize(self):
        self.logger.info(f"Analyzing iOS application '{self.ipa_path}'")

        self.bin_path, self.plist_readable = util.unpacking_ios_app(
            self.ipa_path, self.dir_binary_extraction, working_dir=self.working_dir
        )

        self.bin_path = Path(self.bin_path)
        self.macho_object = lief.parse(self.bin_path.as_posix())
        self.macho_symbols = "\n".join([x.name for x in self.macho_object.symbols])

    def finalize(self):
        if not self.keep_files:
            self.logger.info(
                "Deleting intermediate files generated during the iOS analysis"
            )
            util.delete_support_files_ipa(self.working_dir)
        else:
            self.logger.info(
                "Intermediate files generated during the iOS analysis "
                f"were saved in '{self.working_dir}'"
            )
