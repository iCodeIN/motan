#!/usr/bin/env python3

import logging
import os
import plistlib
import re
import zipfile
from typing import Iterable, List
import shutil
import subprocess
import glob
from biplist import readPlist, writePlistToString


from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import ClassDefItem

logger = logging.getLogger(__name__)


def get_non_empty_lines_from_file(file_name: str) -> List[str]:
    try:
        with open(file_name, "r", encoding="utf-8") as file:
            # Return a list with the non blank lines contained in the file.
            return list(filter(None, (line.rstrip() for line in file)))
    except Exception as e:
        logger.error(f"Error when reading file '{file_name}': {e}")
        raise


# Adapted from https://github.com/pkumza/LiteRadar
def get_libs_to_ignore() -> List[str]:
    return get_non_empty_lines_from_file(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "resources",
            "android_libs_to_ignore.txt",
        )
    )


def check_valid_apk_file(input_file: str):
    if not APK(input_file).is_valid_APK():
        raise ValueError("This file is not a valid apk file")


def check_valid_ipa_file(input_file: str):
    try:
        with zipfile.ZipFile(input_file, "r") as ipa_zip:
            info_plist_file_regex = re.compile(
                r"Payload/.+\.app/info\.plist", re.IGNORECASE
            )

            # Every valid ipa application has an info.plist file.
            info_plist_path = list(
                filter(info_plist_file_regex.match, ipa_zip.namelist())
            )[0]

            with ipa_zip.open(info_plist_path, "r") as info_plist_file:
                plistlib.load(info_plist_file)

    except Exception:
        raise ValueError("This file is not a valid ipa file")


def is_class_implementing_interfaces(clazz: ClassDefItem, interfaces: Iterable[str]):
    """
    Check if a class is implementing a specific list of interfaces.
    """
    return all(interface in clazz.get_interfaces() for interface in interfaces)


def get_list_cpu_type(name_binary):
    """
    Get CPU types of Fat-Binary
    """
    command_check_architecture = ["otool", "-hv", name_binary]
    process_command_check_arch = subprocess.Popen(
        command_check_architecture, stdout=subprocess.PIPE
    )
    out, err = process_command_check_arch.communicate()
    out_string = out.decode("utf-8")
    lines = out_string.split("Mach header")
    list_architecture = []
    for line in lines:
        if len(line) == 2:
            line = line[1]
        values = line.strip().split("\n")
        if len(values) == 2:
            dict_key_value = dict()
            values[0] = values[0].strip().split(" ")
            values[0] = [x for x in values[0] if x != ""]
            values[1] = values[1].strip().split(" ")
            values[1] = [x for x in values[1] if x != ""]
            for index_key in range(0, len(values[0])):
                if values[0][index_key] != "flags":
                    dict_key_value[values[0][index_key]] = values[1][index_key]
                else:
                    dict_key_value[values[0][index_key]] = values[1][index_key:]
            list_architecture.append(dict_key_value)
    list_cpu_type = list()
    list_subtype_cpu = list()
    for x in list_architecture:
        list_cpu_type.append(x["cputype"].lower())
        list_subtype_cpu.append(x["cpusubtype"].lower())
    return list_cpu_type, list_subtype_cpu


def unpacking_ios_app(ipa_path: str, working_dir: str):

    zipfile_output = os.path.join(working_dir, f"{os.path.splitext(os.path.basename(ipa_path))[0]}.zip")
    shutil.copy2(ipa_path, zipfile_output)
    name_subdir = ""
    name_binary = ""
    plist_readable = {}

    with zipfile.ZipFile(zipfile_output, "r") as zipfile_output_ipa:
        for entry in zipfile_output_ipa.infolist():
            normpath = os.path.normpath(entry.filename)
            file_split = normpath.split(os.sep)

            if (
                    file_split[0] == "Payload"
                    and len(file_split) > 2
                    and file_split[1].endswith(".app")
                    and file_split[2].endswith(".plist")
                    and file_split[2].lower() == "info.plist"
            ):
                name_subdir = file_split[1].split(".app")[0]
                read_content_plist = zipfile_output_ipa.read(entry)
                ouput_dir = os.path.join(working_dir, name_subdir)
                os.makedirs(ouput_dir, exist_ok=True)

                with open(os.path.join(ouput_dir, "Info.plist"), "wb+") as plist:
                    plist.write(read_content_plist)

                plist_readable = readPlist(os.path.join(ouput_dir, "Info.plist"))
                bin_name = plist_readable.get('CFBundleExecutable', '')

    with zipfile.ZipFile(zipfile_output, "r") as zipfile_output_ipa:
        for entry in zipfile_output_ipa.infolist():
            normpath = os.path.normpath(entry.filename)
            file_split = normpath.split(os.sep)

            if (
                    file_split[0] == "Payload"
                    and len(file_split) > 2
                    and file_split[1].endswith(".app")
                    and file_split[2] == bin_name
            ):
                name_subdir = file_split[1].split(".app")[0]
                ouput_dir = os.path.join(working_dir, name_subdir)
                binary = zipfile_output_ipa.read(entry)
                name_binary = os.path.join(ouput_dir, name_subdir)
                os.makedirs(ouput_dir, exist_ok=True)
                with open(name_binary, "wb") as binary_output:
                    binary_output.write(binary)

    if name_binary != "":
        try:
            list_cpu_type, list_subtype_cpu = get_list_cpu_type(name_binary)
            # identify cpu type
            if len(list_cpu_type) == 1 and "all" in list_subtype_cpu:
                cpu_choose = list_cpu_type[0]
            elif "arm64" in list_cpu_type:
                cpu_choose = "arm64"
            elif len(list_cpu_type) == 1 and "all" not in list_cpu_type:
                cpu_choose = "{0}{1}".format(list_cpu_type[0], list_subtype_cpu[0])

            logger.debug(
                "Convert binary to specific architecture {}".format(cpu_choose)
            )
            # if is a flat binary we can use arm_64
            if len(list_cpu_type) > 1:
                # get name binary and execute lipo command to extract only 64bit
                binary_64_name = "{0}_{1}".format(name_binary, cpu_choose)
                command_conversion = [
                    "lipo",
                    "-thin",
                    cpu_choose,
                    name_binary,
                    "-output",
                    binary_64_name,
                ]
                subprocess.call(command_conversion, stdout=subprocess.DEVNULL)
            else:
                # otherwise we analyze directly the binary
                binary_64_name = name_binary

            return binary_64_name, plist_readable

        except Exception as e:
            logger.error(e)

    else:
        logger.error("Not found binary")

    return None, None


def delete_support_files_ipa(working_dir_to_delete: str):
    file_list = glob.glob(os.path.join(working_dir_to_delete, "*"))
    for file_to_delete in file_list:
        if os.path.isfile(file_to_delete):
            os.remove(file_to_delete)
        else:
            shutil.rmtree(file_to_delete)
