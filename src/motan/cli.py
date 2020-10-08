#!/usr/bin/env python3

import argparse
from typing import List

from motan.main import perform_analysis


def get_cmd_args(args: List[str] = None):
    """
    Parse and return the command line parameters needed for the script execution.

    :param args: List of arguments to be parsed (by default sys.argv is used).
    :return: The command line needed parameters.
    """

    languages = ["en", "it"]

    parser = argparse.ArgumentParser(
        prog="python3 -m motan.cli",
        description="Find the security vulnerabilities of a mobile application "
        "without needing its source code.",
    )
    parser.add_argument(
        "app_file",
        type=str,
        metavar="FILE",
        help="The path to the mobile application to analyze",
    )
    parser.add_argument(
        "-l",
        "--language",
        choices=languages,
        help="The language used for the vulnerabilities. "
        f"Allowed values are: {', '.join(languages)}",
        default="en",
    )
    parser.add_argument(
        "-i",
        "--ignore-libs",
        action="store_true",
        help="Ignore known third party libraries during the vulnerability analysis",
    )
    return parser.parse_args(args)


def main():
    arguments = get_cmd_args()

    if arguments.app_file:
        arguments.app_file = arguments.app_file.strip(" '\"")

    if arguments.language:
        arguments.language = arguments.language.strip(" '\"")

    perform_analysis(arguments.app_file, arguments.language, arguments.ignore_libs)


if __name__ == "__main__":
    main()
