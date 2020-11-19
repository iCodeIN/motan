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
    keep_files: bool = False,
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

    analysis = None
    found_vulnerabilities: List[VulnerabilityDetails] = []
    failures = 0

    try:
        if platform == "Android":
            manager = AndroidVulnerabilityManager()
            analysis = AndroidAnalysis(input_app_path, language, ignore_libs)

        elif platform == "iOS":
            manager = IOSVulnerabilityManager()
            analysis = IOSAnalysis(input_app_path, language)

        else:
            logger.critical(f"Unknown platform '{platform}'")
            raise ValueError(f"Unknown platform '{platform}'")

        for item in manager.get_all_vulnerability_checks():
            try:
                vulnerability_details = item.plugin_object.check_vulnerability(analysis)
                if vulnerability_details:
                    found_vulnerabilities.append(vulnerability_details)
            except Exception:
                failures += 1
                if fail_fast:
                    # Make the entire vulnerability analysis fail only if the
                    # corresponding flag is enabled.
                    raise

    except Exception as e:
        logger.critical(f"Vulnerability analysis failed: {e}")

        logger.info(
            f"{len(analysis.checked_vulnerabilities)} vulnerabilities checked "
            f"before failure: {', '.join(analysis.checked_vulnerabilities)}"
        )

        if found_vulnerabilities:
            logger.info(
                f"{len(found_vulnerabilities)} vulnerabilities found before failure: "
                f"{', '.join(map(lambda x: x.id, found_vulnerabilities))}"
            )
        else:
            logger.info("0 vulnerabilities found before failure")

        raise

    else:
        # No exceptions were raised, this is a successful vulnerability analysis.
        logger.info(f"Vulnerability analysis finished with {failures} failure(s)")

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

        return found_vulnerabilities

    finally:
        # Cleanup intermediate files even if the analysis failed.
        if analysis and platform == "iOS" and not keep_files:
            logger.info("Deleting all dir and temp files")
            util.delete_support_files_ipa(analysis.working_dir)
        elif not analysis and platform == "iOS":
            util.delete_support_files_ipa(analysis.working_dir)

        # Calculate the total time (in seconds) needed for the analysis.
        analysis_duration = datetime.now() - analysis_start

        logger.info(
            f"Analysis duration: {analysis_duration.total_seconds():.1f} seconds"
        )


def perform_analysis_with_timeout(
    input_app_path: str,
    language: str,
    ignore_libs: bool = False,
    fail_fast: bool = False,
    timeout: int = None,
    keep_files: bool = False,
) -> List[VulnerabilityDetails]:
    with ProcessPool(1) as pool:
        return pool.schedule(
            perform_analysis_without_timeout,
            args=[
                input_app_path,
                language,
                ignore_libs,
                fail_fast,
                keep_files,
            ],
            timeout=timeout,
        ).result()
