#!/usr/bin/env python3

import logging
import os

from yapsy.PluginManager import PluginManager

from motan import categories


class VulnerabilityManager(object):
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

        # Collect all the vulnerability checks contained in the ./vulnerabilities
        # directory. Each vulnerability has an associated .vulnerability file with some
        # metadata and belongs to at least a category (see the base class of each
        # vulnerability).
        self.manager = PluginManager(
            directories_list=[
                os.path.join(
                    os.path.dirname(os.path.realpath(__file__)), "vulnerabilities"
                )
            ],
            plugin_info_ext="vulnerability",
            categories_filter={
                "Manifest": categories.IManifestVulnerability,
                "Code": categories.ICodeVulnerability,
            },
        )
        self.manager.collectPlugins()

    def get_all_vulnerability_checks(self):
        return self.manager.getAllPlugins()
