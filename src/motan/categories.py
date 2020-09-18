#!/usr/bin/env python3

from abc import ABC, abstractmethod

from yapsy.IPlugin import IPlugin

from motan.analysis import Analysis


class IBaseVulnerability(ABC, IPlugin):
    @abstractmethod
    def check_vulnerability(self, analysis_info: Analysis):
        raise NotImplementedError()


class IManifestVulnerability(IBaseVulnerability):
    @abstractmethod
    def check_vulnerability(self, analysis_info: Analysis):
        raise NotImplementedError()


class ICodeVulnerability(IBaseVulnerability):
    @abstractmethod
    def check_vulnerability(self, analysis_info: Analysis):
        raise NotImplementedError()
