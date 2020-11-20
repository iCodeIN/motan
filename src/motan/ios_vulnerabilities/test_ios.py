import zipfile
import os
import sys
import shutil
from biplist import readPlist, writePlistToString

ipa_file = sys.argv[1]
working_dir = "working_dir_ios"

zipfile_output = os.path.join(
    working_dir, f"{os.path.splitext(os.path.basename(ipa_file))[0]}.zip"
)
shutil.copy2(ipa_file, zipfile_output)
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
            bin_name = plist_readable.get("CFBundleExecutable", "")


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
