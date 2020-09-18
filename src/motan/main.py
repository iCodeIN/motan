#!/usr/bin/env python3

import logging
import os
from datetime import datetime

from motan import util
from motan.analysis import Analysis
from motan.manager import VulnerabilityManager

log_level = os.environ.get("LOG_LEVEL", logging.INFO)

# Logging configuration.
logger = logging.getLogger(__name__)
logging.basicConfig(
    format="%(asctime)s> [%(levelname)s][%(name)s][%(funcName)s()] %(message)s",
    datefmt="%d/%m/%Y %H:%M:%S",
    level=log_level,
)

# For the plugin system, log only the error messages and ignore the log level set by
# the user.
logging.getLogger("yapsy").level = logging.WARNING
logging.getLogger("androguard").level = logging.WARNING


def perform_analysis(input_app_path: str, interactive: bool = False):

    if not os.path.isfile(input_app_path):
        logger.critical(f"Unable to find mobile application file '{input_app_path}'")
        raise FileNotFoundError(
            f"Unable to find mobile application file '{input_app_path}'"
        )

    # Needed for calculating the analysis duration.
    analysis_start = datetime.now()

    analysis = Analysis(input_app_path, interactive)
    manager = VulnerabilityManager()

    vulnerability_progress = util.show_list_progress(
        manager.get_all_vulnerability_checks(),
        interactive=interactive,
        unit="vulnerability",
        description="Checking vulnerabilities",
    )

    for vulnerability in vulnerability_progress:
        try:
            if interactive:
                vulnerability_progress.set_description(
                    f"Checking vulnerabilities ({vulnerability.name})"
                )
            vulnerability.plugin_object.check_vulnerability(analysis)
        except Exception as e:
            logger.critical(f"Error during vulnerability analysis: {e}", exc_info=True)
            raise

    # Calculate the total time (in seconds) needed for the analysis.
    analysis_duration = datetime.now() - analysis_start
    logger.info(
        "Analysis duration (sec): {0:.0f}".format(analysis_duration.total_seconds())
    )
