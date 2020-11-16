import lief
from pathlib import Path
import os
import re

binpath = Path(
    os.path.join(
        "/home/dave/Research/motan/src",
        "working_dir_motan_ios",
        "iGoat-Swift_binary",
        "iGoat-Swift_binary_arm64",
    )
)
print(binpath.as_uri())
macho = lief.parse(binpath.as_posix())

## BANNED APIS
# print(macho.symbols)
for x in macho.symbols:
    print(x.name)
dat = "\n".join([x.name for x in macho.symbols])
print(dat)

baned = re.findall(
    "_alloca|_gets|_memcpy|_printf|_scanf|"
    "_sprintf|_sscanf|_strcat|"
    "StrCat|_strcpy|StrCpy|_strlen|StrLen|"
    "_strncat|StrNCat|_strncpy|"
    "StrNCpy|_strtok|_swprintf|_vsnprintf|"
    "_vsprintf|_vswprintf|_wcscat|_wcscpy|"
    "_wcslen|_wcsncat|_wcsncpy|_wcstok|_wmemcpy|"
    "_fopen|_chmod|_chown|_stat|_mktemp",
    dat,
)
print(list(set(baned)))


# for x in macho.imported_functions:
#    print(x.name)

# for x in macho.exported_functions:
#    print(x.name)
# print(macho.imported_functions)
# print(macho.exported_functions)
# for x in macho.symbols:
#    print(x)
