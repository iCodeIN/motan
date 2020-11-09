#!/usr/bin/env python3

import logging
import os
from datetime import datetime
from typing import List

from pebble import ProcessPool

from motan import util
from motan.analysis import AndroidAnalysis, IOSAnalysis
from motan.manager import AndroidVulnerabilityManager, IOSVulnerabilityManager
from motan.vulnerability import VulnerabilityDetails

log_level = os.environ.get("LOG_LEVEL", logging.INFO)

# Logging configuration.
logger = logging.getLogger(__name__)
logging.basicConfig(
    format="%(asctime)s> [%(levelname)s][%(name)s][%(funcName)s()] %(message)s",
    datefmt="%d/%m/%Y %H:%M:%S",
    level=log_level,
)

# For the used libraries, log only the error messages and ignore the log level set by
# the user.
logging.getLogger("yapsy").level = logging.ERROR
logging.getLogger("androguard").level = logging.ERROR


def perform_analysis_without_timeout(
    input_app_path: str,
    language: str,
    ignore_libs: bool = False,
    fail_fast: bool = False,
) -> List[VulnerabilityDetails]:
    # Needed for calculating the analysis duration.
    analysis_start = datetime.now()

    # Make sure the file to analyze is a valid file.
    if not os.path.isfile(input_app_path):
        logger.critical(f"Unable to find mobile application file '{input_app_path}'")
        raise FileNotFoundError(
            f"Unable to find mobile application file '{input_app_path}'"
        )

    # Verify if this is an Android or iOS application, then start the corresponding
    # vulnerability analysis.
    platform = None

    try:
        util.check_valid_apk_file(input_app_path)
        platform = "Android"
    except ValueError:
        pass

    if not platform:
        try:
            util.check_valid_ipa_file(input_app_path)
            platform = "iOS"
        except ValueError:
            pass

    if not platform:
        logger.critical(f"File '{input_app_path}' is not a valid mobile application")
        raise ValueError(f"File '{input_app_path}' is not a valid mobile application")

    if platform == "Android":
        manager = AndroidVulnerabilityManager()
        analysis = AndroidAnalysis(input_app_path, language, ignore_libs)

    elif platform == "iOS":
        manager = IOSVulnerabilityManager()
        analysis = IOSAnalysis(input_app_path, language)

    else:
        logger.critical(f"Unknown platform '{platform}'")
        raise ValueError(f"Unknown platform '{platform}'")

    found_vulnerabilities: List[VulnerabilityDetails] = []

    for item in manager.get_all_vulnerability_checks():
        try:
            vulnerability_details = item.plugin_object.check_vulnerability(analysis)
            if vulnerability_details:
                found_vulnerabilities.append(vulnerability_details)
        except Exception as e:
            if fail_fast:
                logger.critical(
                    f"Error during vulnerability analysis: {e}", exc_info=True
                )
                raise

    # Calculate the total time (in seconds) needed for the analysis.
    analysis_duration = datetime.now() - analysis_start

    logger.info(
        f"{len(analysis.checked_vulnerabilities)} vulnerabilities checked: "
        f"{', '.join(analysis.checked_vulnerabilities)}"
    )

    if found_vulnerabilities:
        logger.info(
            f"{len(found_vulnerabilities)} vulnerabilities found: "
            f"{', '.join(map(lambda x: x.id, found_vulnerabilities))}"
        )
    else:
        logger.info("0 vulnerabilities found")

    logger.info(f"Analysis duration: {analysis_duration.total_seconds():.1f} seconds")

    return found_vulnerabilities


def perform_analysis_with_timeout(
    input_app_path: str,
    language: str,
    ignore_libs: bool = False,
    fail_fast: bool = False,
    timeout: int = None,
) -> List[VulnerabilityDetails]:
    with ProcessPool(1) as pool:
        return pool.schedule(
            perform_analysis_without_timeout,
            args=[
                input_app_path,
                language,
                ignore_libs,
                fail_fast,
            ],
            timeout=timeout,
        ).result()
