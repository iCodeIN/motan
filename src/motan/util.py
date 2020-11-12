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
    process_command_check_arch = subprocess.Popen(command_check_architecture, stdout=subprocess.PIPE)
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


def unpacking_ios_app(ipa_path: str, output_dir_bin: str, working_dir: str):
    """
        Unpacking IPA file
    """
    logger.debug(f"Unpacking f{ipa_path}")

    # create dirs in order to work
    os.makedirs(output_dir_bin, exist_ok=True)

    # get some information about dir
    file_ipa_no_ext = ipa_path.rsplit(".", 1)[0]
    dir_contains_ipa = file_ipa_no_ext.rsplit(os.sep, 1)[0]
    only_name = file_ipa_no_ext.rsplit(os.sep, 1)[-1]
    zip_file = os.path.join(working_dir, "{}.zip".format(only_name))
    output_dir_zip = os.path.join(working_dir, only_name)

    shutil.copy2(ipa_path, zip_file)
    logger.debug("Extract all zip content")
    command_zip = ["unzip", "-q", "-o", zip_file, "-d", output_dir_zip]
    
    subprocess.call(command_zip)
    
    logger.debug("Unpacking iOS app")
    list_ff_files = list()
    for (dirpath, dirnames, filenames) in os.walk(output_dir_zip):
        list_ff_files += [os.path.join(dirpath, file) for file in filenames]
    
    name_binary = ""
    for file_inside in list_ff_files:
        file_split = file_inside.split(os.sep)
        # len(file_split) - len(output_dir_zip.split(os.sep)) == 3 and   \
        if file_split[-1] == file_split[-2].split(".app")[0] and \
                file_split[-2].endswith(".app"):
            # Identify binary file
            name_binary = "{}_binary".format(file_split[-1])
            shutil.copy2(file_inside, name_binary)
    try:
        if name_binary != "":

            list_cpu_type, list_subtype_cpu = get_list_cpu_type(name_binary)

            # identify cpu type
            if len(list_cpu_type) == 1 and "all" in list_subtype_cpu:
                cpu_choose = list_cpu_type[0]
            elif "arm64" in list_cpu_type:
                cpu_choose = "arm64"
            elif len(list_cpu_type) == 1 and "all" not in list_cpu_type:
                cpu_choose = "{0}{1}".format(list_cpu_type[0], list_subtype_cpu[0])
            
            logger.debug("Convert binary to specific architecture {}".format(cpu_choose))

            # get name binary and execute lipo command to extract only 64bit
            binary_64_name = "{0}_{1}".format(name_binary, cpu_choose)
            command_conversion = ["lipo", "-thin", cpu_choose, name_binary, "-output", binary_64_name]
            subprocess.call(command_conversion, stdout=subprocess.DEVNULL)

            # move binary to specific path
            path_bin = os.path.join(output_dir_bin, binary_64_name)

            shutil.move(binary_64_name, path_bin)
            os.remove(name_binary)
            return path_bin
        else:
            logger.error("Not found binary")
            return None
    except Exception as e:
        logger.error(e)
    

def delete_support_files_ipa(working_dir_to_delete: str):
    file_list = glob.glob(os.path.join(working_dir_to_delete, "*"))
    for file_to_delete in file_list:
        if os.path.isfile(file_to_delete):
            os.remove(file_to_delete)
        else:
            shutil.rmtree(file_to_delete)