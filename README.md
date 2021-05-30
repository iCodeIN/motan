# motan

> A tool for **mo**bile application s**t**atic **an**alysis.

[![Ubuntu Build Status](https://github.com/Dado1513/motan/workflows/Ubuntu/badge.svg)](https://github.com/Dado1513/motan/actions?query=workflow%3AUbuntu)
[![Windows Build Status](https://github.com/Dado1513/motan/workflows/Windows/badge.svg)](https://github.com/Dado1513/motan/actions?query=workflow%3AWindows)
[![MacOS Build Status](https://github.com/Dado1513/motan/workflows/MacOS/badge.svg)](https://github.com/Dado1513/motan/actions?query=workflow%3AMacOS)



**motan** (**mo**bile application s**t**atic **an**alysis) is a platform agnostic and
easily extensible modular tool for performing static security assessments of mobile
applications. It can analyze both Android (`apk`) and iOS (`ipa`) applications by
providing an unified JSON report containing details about the identified vulnerabilities
as well as remediation suggestions, web resources for further insights and the location
where the vulnerable code/configuration was found.



## ❱ Publication

*Coming soon*



## ❱ Installation

There are two ways of getting a working copy of motan on your own computer: either
by [using Docker](#docker-image) or by [using directly the source code](#from-source)
in a `Python 3` environment. In both cases, the first thing to do is to get a local
copy of this repository, so open up a terminal in the directory where you want to save
the project and clone the repository:

```Shell
$ git clone https://github.com/Dado1513/motan.git
```

### Docker image

----------------------------------------------------------------------------------------

#### Prerequisites

This is the suggested way of installing motan, since the only requirement is to
have a recent version of Docker installed:

```Shell
$ docker --version
Docker version 19.03.13, build 4484c46d9d
```

#### Install

Execute the following command in the previously created `motan/src/` directory (the
folder containing the `Dockerfile`) to build the Docker image:

```Shell
$ # Make sure to run the command in motan/src/ directory.
$ # It will take some time to download and install all the dependencies.
$ docker build -t motan .
```

When the Docker image is ready, make a quick test to check that everything was
installed correctly:

```Shell
$ docker run --rm -it motan --help
usage: python3 -m cli [-h] [-l {en,it}] [-i] [--fail-fast] [-t TIMEOUT]
...
```

motan is now ready to be used, see the [usage instructions](#-usage) for more
information.

### From source

----------------------------------------------------------------------------------------

#### Prerequisites

The only requirement of this project is a working `Python 3` installation (along with
its package manager `pip`). Depending on your operating system, you might need a
different version of Python, as specified in the table below:

| Python version     | Ubuntu                   | Windows                  | MacOS                    |
|:------------------:|:------------------------:|:------------------------:|:------------------------:|
| **2.x**            | :trollface:              | :trollface:              | :trollface:              |
| **3.6** or lower   | :heavy_multiplication_x: | :heavy_multiplication_x: | :heavy_multiplication_x: |
| **3.7**            | :heavy_check_mark:       | :heavy_check_mark:       | :heavy_check_mark:       |
| **3.8**            | :heavy_check_mark:       | :warning:                | :heavy_check_mark:       |
| **3.9** or greater | :warning:                | :warning:                | :warning:                |

:warning: might work by installing `lief` package manually, since no stable prebuilt
wheels are currently available, but don't expect any support in this scenario.

#### Install

Run the following commands in the main directory of the project (`motan/`) to install
the needed dependencies:

```Shell
$ # Make sure to run the commands in motan/ directory.

$ # The usage of a virtual environment is highly recommended, e.g., virtualenv.
$ # If not using virtualenv (https://virtualenv.pypa.io/), skip the next 2 lines.
$ virtualenv -p python3 venv
$ source venv/bin/activate

$ # Install motan's requirements.
$ python3 -m pip install -r src/requirements.txt
```

After the requirements are installed, make a quick test to check that everything works
correctly:

```Shell
$ cd src/
$ # The following command has to be executed always from motan/src/ directory
$ # or by adding motan/src/ directory to PYTHONPATH environment variable.
$ python3 -m cli --help
usage: python3 -m cli [-h] [-l {en,it}] [-i] [--fail-fast] [-t TIMEOUT]
...
```

motan is now ready to be used, see the [usage instructions](#-usage) for more
information.



## ❱ Usage

*TBD*


## ❱ Vulnerabilities

*TBD*

### ❱ Android Vulnerabilities

### [access_device_id]()
>
>
>

### [access_internet_without_permission]()
>
>
>

### [access_mock_location]()
>
>
>

### [allow_all_hostname]()
>
>
>

### [backup_enabled]()
>
>
>

### [base64_string]()
>
>
>

### [base64_url]()
>
>
>

### [cordova_access_origin_no_csp]()
>
>
>

### [cordova_access_origin_with_csp]()
>
>
>

### [cordova_allow_intent_all_https]()
>
>
>

### [cordova_allow_intent_wildcard]()
>
>
>

### [cordova_allow_navigation_all_https]()
>
>
>

### [cordova_allow_navigation_wildcard]()
>
>
>

### [cordova_no_csp_access_issue]()
>
>
>

### [cordova_no_csp_access_ok]()
>
>
>

### [crypto_constant_iv]()
>
>
>

### [crypto_constant_key]()
>
>
>

### [crypto_constant_salt]()
>
>
>

### [crypto_ecb_cipher]()
>
>
>

### [crypto_keystore_entry_without_password]()
>
>
>

### [crypto_small_iteration_count]()
>
>
>

### [default_scheme_http]()
>
>
>

### [dynamic_code_loading]()
>
>
>

### [empty_permission_group]()
>
>
>

### [exported_component]()
>
>
>

### [exported_content_provider]()
>
>
>

### [exported_without_prefix]()
>
>
>

### [external_storage]()
>
>
>

### [implicit_intent_service]()
>
>
>

### [insecure_connection]()
>
>
>

### [insecure_hostname_verifier]()
>
>
>

### [insecure_socket]()
>
>
>

### [insecure_socket_factory]()
>
>
>

### [intent_filter_misconfiguration]()
>
>
>

### [invalid_server_certificate]()
>
>
>

### [keystore_without_password]()
>
>
>

### [obfuscation_low]()
>
>
>

### [obfuscation_missing]()
>
>
>

### [permission_dangerous]()
>
>
>

### [permission_normal]()
>
>
>

### [runtime_command]()
>
>
>

### [runtime_command_root]()
>
>
>

### [send_sms]()
>
>
>

### [shared_user_id]()
>
>
>

### [sqlite_exec_sql]()
>
>
>

### [system_permission_usage]()
>
>
>

### [webview_allow_file_access]()
>
>
>

### [webview_ignore_ssl_error]()
>
>
>

### [webview_intercept_request]()
>
>
>

### [webview_javascript_enabled]()
>
>
>

### [webview_javascript_interface]()
>
>
>

### [webview_override_url]()
>
>
>

### [world_readable_writable]()
>
>
>


### ❱ iOS Vulnerabilities

### [allow_http_plist]()
>
>
>

### [arc_flag_missing]()
>
>
>

### [code_signature_missing]()
>
>
>

### [encryption_missing]()
>
>
>

### [insecure_api]()
>
>
>

### [insecure_connection_plist]()
>
>
>

### [insecure_random]()
>
>
>

### [insecure_tls_version_plist]()
>
>
>

### [logging_function]()
>
>
>

### [malloc_function]()
>
>
>

### [no_forward_secrecy_plist]()
>
>
>

### [nx_bit_missing]()
>
>
>

### [pie_flag_missing]()
>
>
>

### [restricted_segment_missing]()
>
>
>

### [rpath_set]()
>
>
>

### [stack_canary_missing]()
>
>
>

### [symbols_stripped]()
>
>
>

### [weak_crypto]()
>
>
>

### [weak_hashes]()
>
>
>


## ❱ Contributing

Questions, bug reports and pull requests are welcome on GitHub at [https://github.com/Dado1513/motan](https://github.com/Dado1513/motan).



## ❱ License

*TBD*



## ❱ Team

* [Davide Caputo](https://csec.it/people/davide_caputo/) - Research Assistant & Developer
* [Gabriel Claudiu Georgiu](https://github.com/ClaudiuGeorgiu) - Developer
