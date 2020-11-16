import os
import sys
import shutil
import zipfile
import platform
import subprocess
import glob
from loguru import logger
from biplist import readPlist, writePlistToString, writePlist


def unpacking(file_ipa, dir_binary):
    decompiler_info = {
        "info_plist": None,
        "decomplied_zip": None,
    }

    logger.info("[*] Unpacking {}".format(file_ipa))
    if not os.path.isdir(dir_binary):
        os.mkdir(dir_binary)

    file_ipa_no_ext = file_ipa.rsplit(".", 1)[0]
    dir_ipa = file_ipa_no_ext.rsplit(os.sep, 1)[0]
    only_name = file_ipa_no_ext.rsplit(os.sep, 1)[-1]
    zip_file = "{}.zip".format(file_ipa_no_ext)
    logger.info("[*] Copy file")

    shutil.copy2(file_ipa, zip_file)
    logger.info("[*] Extract all zip content")
    command_zip = ["unzip", "-o", zip_file, "-d", os.path.join(dir_ipa, only_name)]
    # logger.info(command_zip)
    subprocess.call(command_zip)  # , stdout=subprocess.DEVNULL)
    # with zipfile.ZipFile(zip_file, 'r') as zip_ref:
    #    zip_ref.extractall(only_name)

    logger.info("[*] Unpacking iOS app")
    list_ff_files = list()
    for (dirpath, dirnames, filenames) in os.walk(os.path.join(dir_ipa, only_name)):
        list_ff_files += [os.path.join(dirpath, file) for file in filenames]

    # create directories
    name_binary = ""
    dir_plist = os.path.join(dir_ipa, only_name, "plist")
    dir_json = os.path.join(dir_ipa, only_name, "json")
    dir_xml = os.path.join(dir_ipa, only_name, "xml")
    dir_res = os.path.join(dir_ipa, only_name, "res")
    dir_db = os.path.join(dir_ipa, only_name, "db")
    os.makedirs(dir_plist, exist_ok=True)
    os.makedirs(dir_json, exist_ok=True)
    os.makedirs(dir_xml, exist_ok=True)
    os.makedirs(dir_res, exist_ok=True)
    os.makedirs(dir_db, exist_ok=True)

    for file_inside in list_ff_files:
        # if dir_ipa is not None:
        #    file_temp = file_inside.replace(dir_ipa,"")
        # else:
        #    file_temp = file_inside
        file_split = file_inside.split(os.sep)
        # logger.info(file_split[-1])
        if len(file_split) - len(dir_ipa.split(os.sep)) == 4 and file_split[
            -1
        ].endswith(".plist"):
            # IDENTIFY PLIST FILES
            # logger.info(file_split[-1])
            name_plist = file_split[-1]
            readable_plist = readPlist(file_inside)
            print(readable_plist, file=open(os.path.join(dir_plist, name_plist), "w"))
            # writePlist(readable_plist,os.path.join(dir_plist,name_plist),binary=(xml is False))
            # logger.info(readable_plist)
            # shutil.copyfileobj(readable_plist, name_plist)
            # shutil.move(name_plist,os.path.join(dir_plist,name_plist))
        if len(file_split) - len(dir_ipa.split(os.sep)) == 4 and file_split[
            -1
        ].endswith(".json"):
            # IDENTIFY JSON FILES
            # logger.info(file_split[-1])
            name_plist = file_split[-1]
            shutil.copy2(file_inside, name_plist)
            shutil.move(name_plist, os.path.join(dir_json, name_plist))
        if len(file_split) - len(dir_ipa.split(os.sep)) == 4 and file_split[
            -1
        ].endswith(".xml"):
            # IDENTIFY XML FILES
            # logger.info(file_split[-1])
            name_plist = file_split[-1]
            shutil.copy2(file_inside, name_plist)
            shutil.move(name_plist, os.path.join(dir_xml, name_plist))
        if len(file_split) - len(dir_ipa.split(os.sep)) == 4 and (
            file_split[-1].endswith(".sqlite") or file_split[-1].endswith(".sql")
        ):
            # IDENTIFY SQL FILES
            # logger.info(file_split[-1])
            name_plist = file_split[-1]
            shutil.copy2(file_inside, name_plist)
            shutil.move(name_plist, os.path.join(dir_db, name_plist))
        if (
            len(file_split) - len(dir_ipa.split(os.sep)) == 4
            and file_split[-1] == file_split[-2].split(".app")[0]
            and file_split[-2].endswith(".app")
        ):
            # IDENTIFY BINARY FILE
            name_binary = "{}_binary".format(file_split[-1])
            shutil.copy2(file_inside, name_binary)
        else:
            # IDENTIFY OTHER RESOURCES
            name_plist = file_split[-1]
            shutil.copy2(file_inside, name_plist)
            shutil.move(name_plist, os.path.join(dir_res, name_plist))
    # TODO check in case fat binary contains only arm32
    try:
        if name_binary != "":
            list_cpu_type, list_subtype_cpu = get_list_cpu_type(name_binary)

            if len(list_cpu_type) == 1 and "all" in list_subtype_cpu:
                cpu_choose = list_cpu_type[0]
            elif "arm64" in list_cpu_type:
                cpu_choose = "arm64"
            elif len(list_cpu_type) == 1 and "all" not in list_cpu_type:
                cpu_choose = "{0}{1}".format(list_cpu_type[0], list_subtype_cpu[0])
            logger.info("[*] Convert binary to only {}".format(cpu_choose))
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
            shutil.move(binary_64_name, os.path.join(dir_binary, binary_64_name))
        # elif platform.system() != "Darwin":
        #    logger.info("[*] Host isn't MacOS, the binary could be for two architecture arm32 and arm64")
        else:
            logger.error("Not found binary")
    except Exception as e:
        logger.error(e)
    # logger.info("[*] Remove dir {}".format(only_name))
    # shutil.rmtree(os.path.join(dir_ipa,only_name))
    if name_binary != "":
        os.remove(name_binary)
    logger.info("\n")


def get_list_cpu_type(name_binary):
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
            # logger.info(dict_key_value)
            list_architecture.append(dict_key_value)
    list_cpu_type = list()
    list_subtype_cpu = list()
    for x in list_architecture:
        list_cpu_type.append(x["cputype"].lower())
        list_subtype_cpu.append(x["cpusubtype"].lower())
    return list_cpu_type, list_subtype_cpu


def main():
    binary_dir_output = sys.argv[3]
    if sys.argv[1] == "-f":
        file_ipa = sys.argv[2]
        unpacking(file_ipa, binary_dir_output)
    elif sys.argv[1] == "-d":
        dir_ipa = sys.argv[2]
        files_ipa = glob.glob(os.path.join(dir_ipa, "*.ipa"))
        for file_ipa in files_ipa:
            unpacking(file_ipa, binary_dir_output)


if __name__ == "__main__":
    if len(sys.argv) == 4:
        main()
    else:
        print("[*] Usage: python3 unpacking_ios_application.py -f App.ipa BinaryDir\n")
        print("[*] Usage: python3 unpacking_ios_application.py -d DirIpa BinaryDir\n")

    # from App.ipa --> App.zip
    # Inside APp.zip dir Payload
    # Inside Payoload some dir like pipp.app
    # Inside dir pippo.app  file pippo
    # check architecture otool -hv pippo
    # lipo -thin armv7 App -output APP32
    # lipo -thin arm App -output APP64
