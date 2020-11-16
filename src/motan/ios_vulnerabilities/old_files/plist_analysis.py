# -*- coding: utf_8 -*-
"""Module for iOS App Plist Analysis."""

import logging
import os
import plistlib
import sys

import biplist
from biplist import readPlist, writePlistToString

logger = logging.getLogger(__name__)


def convert_bin_xml(bin_xml_file):
    """Convert Binary XML to Readable XML."""
    try:
        plist_obj = readPlist(bin_xml_file)
        data = writePlistToString(plist_obj)
        return data
    except biplist.InvalidPlistException:
        logger.warning("Failed to convert plist")


def check_permissions(p_list):
    """Check the permissions the app requests."""
    # List taken from
    # https://developer.apple.com/library/content/
    # documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html
    logger.info("Checking Permissions")
    permissions = []
    if "NSAppleMusicUsageDescription" in p_list:
        permissions.append(
            {
                "name": "NSAppleMusicUsageDescription",
                "description": "Access Apple Media Library.",
                "reason": p_list["NSAppleMusicUsageDescription"],
            }
        )
    if "NSBluetoothPeripheralUsageDescription" in p_list:
        permissions.append(
            {
                "name": "NSBluetoothPeripheralUsageDescription",
                "description": "Access Bluetooth Interface.",
                "reason": p_list["NSBluetoothPeripheralUsageDescription"],
            }
        )
    if "NSCalendarsUsageDescription" in p_list:
        permissions.append(
            {
                "name": "NSCalendarsUsageDescription",
                "description": "Access Calendars.",
                "reason": p_list["NSCalendarsUsageDescription"],
            }
        )
    if "NSCameraUsageDescription" in p_list:
        permissions.append(
            {
                "name": "NSCameraUsageDescription",
                "description": "Access the Camera.",
                "reason": p_list["NSCameraUsageDescription"],
            }
        )
    if "NSContactsUsageDescription" in p_list:
        permissions.append(
            {
                "name": "NSContactsUsageDescription",
                "description": "Access Contacts.",
                "reason": p_list["NSContactsUsageDescription"],
            }
        )
    if "NSHealthShareUsageDescription" in p_list:
        permissions.append(
            {
                "name": "NSHealthShareUsageDescription",
                "description": "Read Health Data.",
                "reason": p_list["NSHealthShareUsageDescription"],
            }
        )
    if "NSHealthUpdateUsageDescription" in p_list:
        permissions.append(
            {
                "name": "NSHealthUpdateUsageDescription",
                "description": "Write Health Data.",
                "reason": p_list["NSHealthUpdateUsageDescription"],
            }
        )
    if "NSHomeKitUsageDescription" in p_list:
        permissions.append(
            {
                "name": "NSHomeKitUsageDescription",
                "description": "Access HomeKit configuration data.",
                "reason": p_list["NSHomeKitUsageDescription"],
            }
        )
    if "NSLocationAlwaysUsageDescription" in p_list:
        permissions.append(
            {
                "name": "NSLocationAlwaysUsageDescription",
                "description": "Access location information at all times.",
                "reason": p_list["NSLocationAlwaysUsageDescription"],
            }
        )
    if "NSLocationUsageDescription" in p_list:
        permissions.append(
            {
                "name": "NSLocationUsageDescription",
                "description": (
                    "Access location information" " at all times (< iOS 8)."
                ),
                "reason": p_list["NSLocationUsageDescription"],
            }
        )
    if "NSLocationWhenInUseUsageDescription" in p_list:
        permissions.append(
            {
                "name": "NSLocationWhenInUseUsageDescription",
                "description": (
                    "Access location information when" " app is in the foreground."
                ),
                "reason": p_list["NSLocationWhenInUseUsageDescription"],
            }
        )
    if "NSMicrophoneUsageDescription" in p_list:
        permissions.append(
            {
                "name": "NSMicrophoneUsageDescription",
                "description": "Access microphone.",
                "reason": p_list["NSMicrophoneUsageDescription"],
            }
        )
    if "NSMotionUsageDescription" in p_list:
        permissions.append(
            {
                "name": "NSMotionUsageDescription",
                "description": "Access the device’s accelerometer.",
                "reason": p_list["NSMotionUsageDescription"],
            }
        )
    if "NSPhotoLibraryUsageDescription" in p_list:
        permissions.append(
            {
                "name": "NSPhotoLibraryUsageDescription",
                "description": "Access the user’s photo library.",
                "reason": p_list["NSPhotoLibraryUsageDescription"],
            }
        )
    if "NSRemindersUsageDescription" in p_list:
        permissions.append(
            {
                "name": "NSRemindersUsageDescription",
                "description": "Access the user’s reminders.",
                "reason": p_list["NSRemindersUsageDescription"],
            }
        )
    if "NSVideoSubscriberAccountUsageDescription" in p_list:
        permissions.append(
            {
                "name": "NSVideoSubscriberAccountUsageDescription",
                "description": "Access the user’s TV provider account.",
                "reason": p_list["NSVideoSubscriberAccountUsageDescription"],
            }
        )

    return permissions


insecure_tls = ["TLSv1.0", "TLSv1.1"]


# Enhanced version made by Talos with love ;)
# Check for NSExceptionRequiresForwardSecrecy == FALSE e NSExceptionMinimumTLSVersion >= 1.2 +
# TODO check cipher_suite https://github.com/OWASP/owasp-mstg/blob/master/Document/0x06g-Testing-Network-Communication.md
def check_insecure_connections(p_list):
    """Check info.plist for insecure connection configurations."""
    logger.info("Checking for Insecure Connections")

    inseccon = {}

    insecure_connections = []
    insecure_tls_dic = []
    no_forward_secr = []
    allow_http = []

    if "NSAppTransportSecurity" in p_list:
        ns_app_trans_dic = p_list["NSAppTransportSecurity"]
        if "NSExceptionDomains" in ns_app_trans_dic:
            for key in ns_app_trans_dic["NSExceptionDomains"]:
                # print(ns_app_trans_dic['NSExceptionDomains'][key])
                insecure_connections.append(key)
                if (
                    "NSExceptionRequiresForwardSecrecy"
                    in ns_app_trans_dic["NSExceptionDomains"][key]
                ):
                    if (
                        ns_app_trans_dic["NSExceptionDomains"][key][
                            "NSExceptionRequiresForwardSecrecy"
                        ]
                        is False
                    ):
                        # print(key['NSExceptionRequiresForwardSecrecy'])
                        no_forward_secr.append(key)
                if (
                    "NSExceptionMinimumTLSVersion"
                    in ns_app_trans_dic["NSExceptionDomains"][key]
                ):
                    if (
                        ns_app_trans_dic["NSExceptionDomains"][key][
                            "NSExceptionMinimumTLSVersion"
                        ]
                        in insecure_tls
                    ):
                        insecure_tls_dic.append(key)
                        # print(key['NSExceptionMinimumTLSVersion'])
                if (
                    ns_app_trans_dic["NSExceptionDomains"][key][
                        "NSExceptionAllowsInsecureHTTPLoads"
                    ]
                    is True
                ):
                    # print(key['NSExceptionRequiresForwardSecrecy'])
                    allow_http.append(key)
        if "NSAllowsArbitraryLoads" in ns_app_trans_dic:
            if ns_app_trans_dic["NSAllowsArbitraryLoads"] is True:
                insecure_connections.append(p_list["NSAppTransportSecurity"])

    # print('TLS' + str(insecure_tls_dic))
    # print('ForwardSecrecy' + str(no_forward_secr))
    # print('AllowHTTP' + str(allow_http))
    # print('InsecureConn' + str(insecure_connections))

    inseccon["InsecureConnections"] = insecure_connections
    inseccon["NoForwardSecrecy"] = no_forward_secr
    inseccon["AllowHTTP"] = allow_http
    inseccon["InsecureTLSVersion"] = insecure_tls_dic

    # print(inseccon)
    return inseccon


# TODO Analyze a generic plist file e not only Info.plist
def plist_analysis(src, is_source):
    """Plist Analysis."""
    try:
        logger.info("iOS Info.plist Analysis Started")
        plist_info = {
            "bin_name": "",
            "bin": "",
            "id": "",
            "version": "",
            "build": "",
            "sdk": "",
            "pltfm": "",
            "min": "",
            "plist_xml": "",
            "permissions": [],
            "inseccon": [],
            "bundle_name": "",
            "build_version_name": "",
            "bundle_url_types": [],
            "bundle_supported_platforms": [],
            "bundle_localizations": [],
            "multiple_plist": [],
        }
        plist_file = None
        multiple_plist = []

        if is_source:
            logger.info("Finding Info.plist in iOS Source")
            app_plist_file = "Info.plist"
            extensions = ".plist"
            for dirpath, _dirnames, files in os.walk(src):
                for name in files:
                    if "__MACOSX" not in dirpath and name == app_plist_file:
                        plist_file = os.path.join(dirpath, name)
                    if (
                        "__MACOSX" not in dirpath
                        and os.path.splitext(name)[-1].lower() in extensions
                        and name != app_plist_file
                    ):
                        multiple_plist.append(os.path.join(dirpath, name))
                # print(plist_files)
            # TODO mettere i path ai file memorizzati nell'object storage
            plist_info["multiple_plist"] = multiple_plist

        else:
            logger.info("Finding Info.plist in iOS Binary")
            dirs = os.listdir(src)
            dot_app_dir = ""
            for dir_ in dirs:
                if dir_.endswith(".app"):
                    dot_app_dir = dir_
                    break
            bin_dir = os.path.join(src, dot_app_dir)  # Full Dir/Payload/x.app
            plist_file = os.path.join(bin_dir, "Info.plist")
        if not os.path.exists(plist_file):
            logger.warning("Cannot find Info.plist file. Skipping Plist Analysis.")
        else:
            # Generic Plist Analysis
            plist_obj = plistlib.readPlist(plist_file)
            plist_info["plist_xml"] = plistlib.writePlistToBytes(plist_obj).decode(
                "utf-8", "ignore"
            )
            if "CFBundleDisplayName" in plist_obj:
                plist_info["bin_name"] = plist_obj["CFBundleDisplayName"]
            else:
                if not is_source:
                    # For iOS IPA
                    plist_info["bin_name"] = dot_app_dir.replace(".app", "")
            if "CFBundleExecutable" in plist_obj:
                plist_info["bin"] = plist_obj["CFBundleExecutable"]
            if "CFBundleIdentifier" in plist_obj:
                plist_info["id"] = plist_obj["CFBundleIdentifier"]

            # build
            if "CFBundleVersion" in plist_obj:
                plist_info["build"] = plist_obj["CFBundleVersion"]
            if "DTSDKName" in plist_obj:
                plist_info["sdk"] = plist_obj["DTSDKName"]
            if "DTPlatformVersion" in plist_obj:
                plist_info["pltfm"] = plist_obj["DTPlatformVersion"]
            if "MinimumOSVersion" in plist_obj:
                plist_info["min"] = plist_obj["MinimumOSVersion"]

            plist_info["bundle_name"] = plist_obj.get("CFBundleName", "")
            plist_info["bundle_version_name"] = plist_obj.get(
                "CFBundleShortVersionString", ""
            )
            plist_info["bundle_url_types"] = plist_obj.get("CFBundleURLTypes", [])
            plist_info["bundle_supported_platforms"] = plist_obj.get(
                "CFBundleSupportedPlatforms", []
            )
            plist_info["bundle_localizations"] = plist_obj.get(
                "CFBundleLocalizations", []
            )

            # Check possible app-permissions
            plist_info["permissions"] = check_permissions(plist_obj)
            plist_info["inseccon"] = check_insecure_connections(plist_obj)
        print(plist_info)
    except Exception as e:
        logger.exception("Reading from Info.plist")


## TODO CAPIRE SE HA SENSO
def other_plist_analysis(src, is_source):
    """Plist Analysis."""
    try:
        logger.info("Other Plist Analysis Started")
        plist_info = {
            "bin_name": "",
            "bin": "",
            "id": "",
            "version": "",
            "build": "",
            "sdk": "",
            "pltfm": "",
            "min": "",
            "plist_xml": "",
            "permissions": [],
            "inseccon": [],
            "bundle_name": "",
            "build_version_name": "",
            "bundle_url_types": [],
            "bundle_supported_platforms": [],
            "bundle_localizations": [],
        }
        plist_files = []

        if is_source:
            logger.info("Finding Info.plist in iOS Source")
            extensions = ".plist"
            app_plist_file = "Info.plist"
            for dirpath, _dirnames, files in os.walk(src):
                for name in files:
                    if (
                        "__MACOSX" not in dirpath
                        and os.path.splitext(name)[-1].lower() in extensions
                        and name != app_plist_file
                    ):
                        plist_files.append(os.path.join(dirpath, name))

            print(plist_files)

        else:
            logger.info("Finding Info.plist in iOS Binary")
            dirs = os.listdir(src)
            dot_app_dir = ""
            for dir_ in dirs:
                if dir_.endswith(".app"):
                    dot_app_dir = dir_
                    break
            bin_dir = os.path.join(src, dot_app_dir)  # Full Dir/Payload/x.app
            plist_file = os.path.join(bin_dir, "Info.plist")

        if not plist_files:
            logger.warning("Cannot find Other .plist files. Skipping Plist Analysis.")
        else:
            for plist_file in plist_files:
                # Generic Plist Analysis
                plist_obj = plistlib.readPlist(plist_file)
                plist_info["plist_xml"] = plistlib.writePlistToBytes(plist_obj).decode(
                    "utf-8", "ignore"
                )
                if "CFBundleDisplayName" in plist_obj:
                    plist_info["bin_name"] = plist_obj["CFBundleDisplayName"]
                else:
                    if not is_source:
                        # For iOS IPA
                        plist_info["bin_name"] = dot_app_dir.replace(".app", "")
                if "CFBundleExecutable" in plist_obj:
                    plist_info["bin"] = plist_obj["CFBundleExecutable"]
                if "CFBundleIdentifier" in plist_obj:
                    plist_info["id"] = plist_obj["CFBundleIdentifier"]

                # build
                if "CFBundleVersion" in plist_obj:
                    plist_info["build"] = plist_obj["CFBundleVersion"]
                if "DTSDKName" in plist_obj:
                    plist_info["sdk"] = plist_obj["DTSDKName"]
                if "DTPlatformVersion" in plist_obj:
                    plist_info["pltfm"] = plist_obj["DTPlatformVersion"]
                if "MinimumOSVersion" in plist_obj:
                    plist_info["min"] = plist_obj["MinimumOSVersion"]

                plist_info["bundle_name"] = plist_obj.get("CFBundleName", "")
                plist_info["bundle_version_name"] = plist_obj.get(
                    "CFBundleShortVersionString", ""
                )
                plist_info["bundle_url_types"] = plist_obj.get("CFBundleURLTypes", [])
                plist_info["bundle_supported_platforms"] = plist_obj.get(
                    "CFBundleSupportedPlatforms", []
                )
                plist_info["bundle_localizations"] = plist_obj.get(
                    "CFBundleLocalizations", []
                )

                # Check possible app-permissions
                plist_info["permissions"] = check_permissions(plist_obj)
                plist_info["inseccon"] = check_insecure_connections(plist_obj)
                print(plist_info)

    except Exception:
        logger.exception("Reading from Info.plist")


def main():
    dir_plist = sys.argv[1]
    plist_analysis(dir_plist, True)
    # other_plist_analysis(dir_plist,True)


if __name__ == "__main__":
    if len(sys.argv) == 2:
        main()
    else:
        print("[*] Usage: python3 plist_analysis.py plist_Dir\n")
