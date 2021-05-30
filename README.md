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
usage: python3 -m motan.cli [-h] [-l {en,it}] [-i] [--fail-fast] [-t TIMEOUT]
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
$ python3 -m motan.cli --help
usage: python3 -m motan.cli [-h] [-l {en,it}] [-i] [--fail-fast] [-t TIMEOUT]
...
```

motan is now ready to be used, see the [usage instructions](#-usage) for more
information.



## ❱ Usage

From now on, motan will be considered as an executable availabe as `motan`, so you need to adapt the commands according to how you install the tool:

* **Docker image**: a local directory containing the application to analyze has to be
mounted to `/workdir` in the container (e.g., the current directory `"${PWD}"`), so the
command:
    ```Shell
    $ motan [params...]
    ```
    becomes:
    ```Shell
    $ docker run --rm -it -u $(id -u):$(id -g) -v "${PWD}":"/workdir" motan [params...]
    ```

* **From source**: every instruction has to be executed from the `motan/src/`
directory (or by adding `motan/src/` directory to `PYTHONPATH` environment
variable) and the command:
    ```Shell
    $ motan [params...]
    ```
    becomes:
    ```Shell
    $ python3 -m motan.cli [params...]
    ```

Let's start by looking at the help message:

```Shell

$ motan --help
motan [-h] [-l {en,it}] [-i] [--fail-fast] [-t TIMEOUT] [--keep-files] <FILE>
```
There is only one mandatory parameters : `<FILE>`, the path (relative or absolute) to
the apk file to analyze.

* `-l {en,it}, --language {en,it}`, The language used for the vulnerabilities. Allowed values are: en, it.

* `-i, --ignore-libs`, Ignore known third party libraries during the vulnerability analysis (only for Android).

* `--fail-fast`, Make the entire analysis fail on the first failed vulnerability check.
  
* `-t TIMEOUT, --timeout TIMEOUT` Make the analysis fail if it takes longer than timeout (in seconds) to complete. By default a timeout of 1200 seconds (20 minutes) is used.

* `--keep-files`, Keep intermediate files generated during the analysis (only for iOS).


## ❱ Vulnerabilities

The vulnerabilities checked in motan are divided into two macro-categories: **[Android Vulnerabilities](#-android-vulnerabilities)** and **[iOS Vulnerabilities](#-ios-vulnerabilities)**.

### ❱ Android Vulnerabilities

### [access_device_id](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/access_device_id)
> This app has code getting the "device id (IMEI)" (using `TelephonyManager.getDeviceId()` ) in order to identify the specific device. 
> This approach has three major drawbacks: i) it is unusable on non-phones devices, ii) it persists across device data wipes, iii) it needs special privilege to be executed (`READ_PHONE_STATE` permission).

### [access_internet_without_permission](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/access_internet_without_permission)
> This app contains code for Internet accessing but does not have `"android.permission.INTERNET"` use-permission in `AndroidManifest.xml`. 
> This may be caused by an app misconfiguration or by a malicious app that tries to access the network interface without having the proper permission.

### [access_mock_location](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/access_mock_location)
> Found `"android.permission.ACCESS_MOCK_LOCATION"` permission in the Android Manifest. 
> This permission only works in emulated environments and is deprecated since API LEVEL 23.

### [allow_all_hostname](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/allow_all_hostname)
> This app does not check the validation of the CN (Common Name) in the SSL certificate (`"ALLOW_ALL_HOSTNAME_VERIFIER"` field or `"AllowAllHostnameVerifier"` class). 
> This is a critical vulnerability and allows attackers to implement MitM attacks with their valid certificate without your knowledge. Deprecated from Android API 22. 
> This behavior also represents a violation in OWASP Mobile TOP 10 Security Risks.

### [backup_enabled](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/backup_enabled)
> ADB Backup is ENABLED for this app (default: ENABLED). 
> ADB Backup is a good tool for backing up all of your files. If enabled, people with physical access to the device can copy all of the sensitive data of the app. 
> The sensitive data may include lifetime access token, username or password etc.

### [base64_string](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/base64_string)
> This app contains Base64 encoded string(s). Please note that security is not the intent of the encoding step. 
> Rather, the intent of the encoding is to encode non-HTTP-compatible characters that may be contained in usernames or passwords into characters that are HTTP-compatible.

### [base64_url](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/base64_url)
> This app contains Base64 encoded url(s). Please note that security is not the intent of the encoding step. 
> Rather, the intent of the encoding is to encode non-HTTP-compatible characters that may be contained in usernames or passwords into characters that are HTTP-compatible.

### [cordova_access_origin_no_csp](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/cordova_access_origin_no_csp)
> The app does not configure the Network Request Whitelist options properly in its Cordova `config.xml` file. 
> The Network Request Whitelist options control which network requests (e.g., images and XHRs) are allowed to be made. Cordova application includes `<access origin="*">` by default.

### [cordova_access_origin_with_csp](https://github.com/Dado1513/motan/blob/master/src/motan/android_vulnerabilities/cordova_access_origin_with_csp/details_en.json)
> The app configures the Network Request Whitelist options to accept plain HTTP URLs. 
> The Network Request Whitelist options control which network requests (e.g., images and XHRs) are allowed to be made. 
> The loading of HTTP URLs or the inclusion of the wildcard filter is not recommended.

### [cordova_allow_intent_all_https](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/cordova_allow_intent_all_https)
> The app configures the Intent Whitelist options to accept HTTPS URLs that come from any domain. 
> The Intent Whitelist options control which URLs the app is allowed to ask the system to open.

### [cordova_allow_intent_wildcard](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/cordova_allow_intent_wildcard)
> The app does not configure the Intent Whitelist options properly in its Cordova `config.xml` file. 
> The Intent Whitelist options control which URLs the app is allowed to ask the system to open. By default, no external URLs are allowed. 
> The loading of HTTP URLs or the inclusion of the wildcard filter is not recommended.

### [cordova_allow_navigation_all_https](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/cordova_allow_navigation_all_https)
> The app configures the Navigation Whitelist options to accept HTTPS connections that come from any domain. 
> The Navigation Whitelist options control which URLs (both files and websites) the WebView itself can be navigated to

### [cordova_allow_navigation_wildcard](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/cordova_allow_navigation_wildcard)
> The app does not configure the Navigation Whitelist options properly in its Cordova `config.xml` file. 
> The Navigation Whitelist options control which URLs (both files and websites) the WebView itself can be navigated to. A wildcard can be used to whitelist the entire network, over HTTP and HTTPS without any restriction and thus it is not recommended. 
> Indeed, a too permissive configuration may allow the loading non-https scheme or content that comes from external non-trusted parties. By default, navigations only to `file://` URLs, are allowed.

### [cordova_no_csp_access_issue](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/cordova_no_csp_access_issue)
> The app does not include a Content Security Policy (CSP). The CSP controls which network requests (e.g., images and XHRs) are allowed to be made (via WebView directly). 
> The CSP is a powerful feature since it allows the filtering of all types of requests that are not configurable using the Network Whitelist options (e.g., `<video>` & WebSockets are not blocked).

### [cordova_no_csp_access_ok](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/cordova_no_csp_access_ok)
> The app does not include a Content Security Policy (CSP). The CSP controls which network requests (e.g., images and XHRs) are allowed to be made (via WebView directly). 
> The CSP is a powerful feature since it allows the filtering of all types of requests that are not configurable using the Network Whitelist options (e.g., `<video>` & WebSockets are not blocked).

### [crypto_constant_iv](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/crypto_constant_iv)
> If the provided initialization vector (IV) is not random, then encrypting a particular piece of information with a symmetric key will yield the same result every time encryption is applied to that information with the same symmetric key. 
> An attacker with access to the encrypted information can then infer the actual information by just analyzing and comparing the encrypted results.

### [crypto_constant_key](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/crypto_constant_key)
> Apps that store encryption keys in the source code are vulnerable to forgery attacks and information leaks. 
> Android apps can use block cipher algorithms to encrypt sensitive information using the Cipher API. The Cipher API expects a key, if such a key used for encryption/decryption is saved in the source code, then an attacker can get access to it and abuse it.

### [crypto_constant_salt](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/crypto_constant_salt)
> If the salt being used is constant, then the symmetric key can be re-created by an attacker if the attacker has access to the password. 
> An attacker can precompute a dictionary of symmetric keys for known passwords and use them to decrypt information.

### [crypto_ecb_cipher](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/crypto_ecb_cipher)
> Apps that use a Block Cipher algorithm in ECB mode for encrypting sensitive information are vulnerable to exposing leaking information. The Cipher API enables developers to specify which block cipher algorithm to use and in which mode. 
> If the app uses the block cipher algorithm AES in ECB mode to encrypt sensitive information then an attacker can break the encryption to get access to the sensitive information. 
> An app can explicitly specify that it wants to use AES in ECB mode or it can specify that it will just use AES without explicitly specifying the mode, in which case Android will use the ECB mode by default.

### [crypto_keystore_entry_without_password](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/crypto_keystore_entry_without_password)
> Apps that store encryption keys without any protection parameter in a keystore accessible by other apps are vulnerable to information exposure. Keystore provides `setEntry` API to store a key entry. 
> Along with the alias and the key, `setEntry` API takes an instance of `ProtectionParameter` as argument to protect the contents of the entry. 
> If an entry is stored in a keystore with `null` as the `ProtectionParameter` argument to `setEntry` API, then any app with access to the keystore and aware of the alias can retrieve the entry.

### [crypto_small_iteration_count](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/crypto_small_iteration_count)
> An iteration count smaller than 1000 passed to `PBEParameterSpec` and `PBEKeySpec` constructors is insecure.

### [debuggable_application](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/debuggable_application)
> DEBUG mode is **ON** (`android:debuggable="true"` in `AndroidManifest.xml`). 
> Debug mode is extremely discouraged in production since malicious users can debug the app and sniff verbose error information through Logcat.

### [default_scheme_http](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/default_scheme_http)
> The app uses "HttpHost", but the default scheme is "HTTP" or "HttpHost.DEFAULT_SCHEME_NAME (HTTP)". 
> Accessing URLs in plain HTTP is a security hazard since a malicious user could intercept and/or modify the exchanged data.

### [dynamic_code_loading](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/dynamic_code_loading)
> The app contains code that dynamically loads classes from `.jar` and `.apk` files containing a `classes.dex` entry. 
> This can be used to execute code not installed as part of an application. This behavior is a security hazard since malicious code could be loaded and executed in the context of the app.


### [empty_permission_group](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/empty_permission_group)
> Found a user-defined empty permissionGroup in the Android Manifest. 
> Setting the "permissionGroup" attribute to an empty value will make the permission definition invalid and no other applications will be able to use the permission.

### [exported_component](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/exported_component)
> Found "exported" components (except for Launcher) for receiving outside applications' actions (`AndroidManifest.xml`). 
> These components can be initialized by other apps and used maliciously.

### [exported_content_provider](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/exported_content_provider)
> Found "exported" ContentProvider, allowing any other app on the device to access it (`AndroidManifest.xml`).

### [exported_without_prefix](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/exported_without_prefix)
> Found exported components lacking "android:" prefix in "exported" attribute (`AndroidManifest.xml`).

### [external_storage](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/external_storage)
> Found external storage access API. Please remember not to write security-critical files to external storage.

### [implicit_intent_service](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/implicit_intent_service)
> The application contains implicit Intents for starting Services. 
> Using an implicit Intent to start a service is a security hazard because you cannot be certain of what service will respond to the intent, and the user cannot see which service starts.

### [insecure_connection](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/insecure_connection)
> The application contains URLs that are **NOT** under SSL. 
> This is a security hazard since information exchanged with those URLs can be intercepted and altered by a malicious user.

### [insecure_hostname_verifier](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/insecure_hostname_verifier)
> The app allows self-defined HOSTNAME VERIFIER to accept all Common Names (CN). 
> This is a critical vulnerability and allows attackers to do MitM attacks with their valid certificate without your knowledge. 
> This behavior also represents a violation in OWASP Mobile TOP 10 Security Risks.

### [insecure_socket](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/insecure_socket)
> Use of `SSLCertificateSocketFactory.createSocket()` without parameters or with an `InetAddress` as the first parameter does not preform hostname verifications by default. 
 > Those sockets are vulnerable to Man-in-the-Middle (MitM) attacks.

### [insecure_socket_factory](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/insecure_socket_factory)
> The app contains code that relies on instances of socket factory with all SSL security checks disabled, using an optional handshake timeout and SSL session cache.
> Those sockets are vulnerable to Man-in-the-Middle (MitM) attacks

### [intent_filter_misconfiguration](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/intent_filter_misconfiguration)
> The app contains misconfiguration in \"intent-filter\" of at least one component of the `AndroidManifest.xml`.

### [invalid_server_certificate](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/invalid_server_certificate)
> The app **DOES NOT** check the validation of SSL Certificates. It allows self-signed, expired or mismatch CN certificates for SSL connection. 
> This is a critical vulnerability and allows attackers to do MitM attacks without your knowledge.
> If you are transmitting users' username or password, this sensitive information may be leaked.

### [keystore_without_password](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/keystore_without_password)
> The Keystores seem **NOT** protected by password. 
> This is a security hazard since malicious users that have physical access to the Keystore file can access the keys and certificates contained in it.

### [obfuscation_low](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/obfuscation_low)
> The app seems using some code obfuscation, but a relevant part of code seems not using any obfuscation technique.

### [obfuscation_missing](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/obfuscation_missing)
> The app seems not using sufficient code obfuscation.

### [permission_dangerous](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/permission_dangerous)
> The protection level of the below classes is "dangerous", allowing any other apps to access this permission (`AndroidManifest.xml`). 
> The app should declare the permission with the `"android:protectionLevel"` of "signature" or "signatureOrSystem" so that other apps cannot register and receive messages for the app.
> `android:protectionLevel=\"signature\"` ensures that apps which request a permission must be signed with the same certificate as the application that declared the permission.

### [permission_normal](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/permission_normal)
> At least one class declared in the Android Manifest is protected with a custom permission, declared with a "normal" or "default" permission level. 
> This allows malicious apps to register and receive messages for this app

### [runtime_command](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/runtime_command)
> The app is using critical function `Runtime.getRuntime().exec(\"...\")`. 

### [runtime_command_root](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/runtime_command_root)
> The app requests for "root" permission through the command `Runtime.getRuntime().exec(\"su\")`. 
> This behavior could be used either by a benign app to check its execution environment or by a malicious app to gain all the privileges.

### [send_sms](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/send_sms)
> The app has code for sending SMS messages (`sendDataMessage`, `sendMultipartTextMessage` or `sendTextMessage`) that could be a cost for the user if maliciously exploited.

### [shared_user_id](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/shared_user_id)
> The app uses `sharedUserId` attribute. If this attribute is set to the same value for two or more applications, they will all share the same ID — provided that they are also signed by the same certificate. 
> Application with the same user ID can share permissions, access each other's data and, if desired, run in the same process. 
> If one of the applications is compromised, it can disruptively access to the entire ecosystem.

### [sqlite_exec_sql](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/sqlite_exec_sql)
> Android allows apps to save data in a local database called SQLite. SQL queries are used to interact with the SQLite database. `execSQL()` method of SQLite allows developers to execute queries such as `INSERT/DELETE/UPDATE` which do not return any result. 
> If an app uses inputs (e.g., user input via UI or data from web) to create a SQL statement to be executed via `execSQL()` method, then the app may be vulnerable to SQL injection attack.

### [system_permission_usage](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/system_permission_usage)
> This app uses critical permissions that allow the management of filesystem and packages (e.g. `"android.permission.MOUNT_FORMAT_FILESYSTEMS"` and `"android.permission.INSTALL_PACKAGES"`). 
> The use of this permissions should be confined only to system apps by device manufacturer or Google. If not, it may be a malicious app.

### [webview_allow_file_access](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/webview_allow_file_access)
> Found `setAllowFileAccess(true)` or not set (enabled by default) in WebView. 
> The attackers could inject malicious script into WebView and exploit the opportunity to access local resources.

### [webview_ignore_ssl_error](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/webview_ignore_ssl_error)
> An Android app can display web pages by loading HTML/JavaScript files in a WebView. 
> A WebView loading an HTML/JavaScript file from a server using SSL/TLS can throw an SSL exception if an incorrect certificate is presented by the server or if the app does not trust the Certificate Authority that has signed the certificate for that server. 
> Android provides the `WebViewClient` API to manage communication between the app and the server. One of the methods in the API (`onReceivedSslError`) allows an app to cancel or proceed with response from the server when an SSL error occurs. 
> If the app chooses to proceed with the response then the app is vulnerable to MITM attacks because a malicious server can create a fake certificate and still communicate with the app.

### [webview_intercept_request](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/webview_intercept_request)
> Android allows apps to load resources (e.g, JavaScript, CSS files etc.) in a web page in a WebView, and control the resources being loaded in a webpage via the `shouldInterceptRequest` method in `WebViewClient`. 
> The `shouldInterceptRequest` method takes an instance of WebView and the resource request as input and returns a response object. 
> If the response object returned is `null` then the WebView is loaded with the web page containing the resource that was requested. But if a non-`null` response is returned then the WebView is loaded with the web page containing the non-`null` response. 
> If the app does not validate the resource in `shouldInterceptRequest` method of `WebViewClient`, any resource can be loaded into WebView.

### [webview_javascript_enabled](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/webview_javascript_enabled)
> Found `"setJavaScriptEnabled(true)"` in WebView. 
> Enabling JavaScript exposes to malicious injection of code that would be executed with the same permissions (XSS attacks).
>
>

### [webview_javascript_interface](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/webview_javascript_interface)
> `"addJavascriptInterface\` method was found in the code. 
> Use of this method in a WebView containing untrusted content could allow an attacker to manipulate the host application in unintended ways, executing Java code with the permissions of the host application.

### [webview_override_url](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/webview_override_url)
> Android allows apps to display web content in a WebView, and control navigation across webpages via the `shouldOverrideUrlLoading` method in `WebViewClient`. 
> The `shouldOverrideUrlLoading` method takes an instance of WebView and the page request as input and returns a boolean. 
> If `true` is returned then the host application handles the request else if `false` is returned then the current WebView handles the request. 
> If the app does not validate the page request in `shouldOverrideUrlLoading` before loading it in the WebView, any web page provided by the server will be loaded into WebView. By default `shouldOverrideUrlLoading` returns `false` all the time.

### [world_readable_writable](https://github.com/Dado1513/motan/tree/master/src/motan/android_vulnerabilities/world_readable_writable)
> Found code that allows file access in `"MODE_WORLD_READABLE"` or `"MODE_WORLD_WRITEABLE"` mode which were deprecated in API Level 17 and removed since API Level 24. 
> Creating world-readable or world-writable files is very dangerous, and likely to cause security holes in applications.



### ❱ iOS Vulnerabilities

### [allow_http_plist](https://github.com/Dado1513/motan/tree/master/src/motan/ios_vulnerabilities/allow_http_plist)
> The application allows the use of the HTTP protocol.

### [arc_flag_missing](https://github.com/Dado1513/motan/tree/master/src/motan/ios_vulnerabilities/arc_flag_missing)
> The binary is not compiled with Automatic Reference Counting (ARC) flag. 
> ARC is a compiler feature that provides automatic memory management of Objective-C objects and is an exploit mitigation mechanism against memory corruption vulnerabilities.

### [code_signature_missing](https://github.com/Dado1513/motan/tree/master/src/motan/ios_vulnerabilities/code_signature_missing)
> The binary does not have a code signature.

### [encryption_missing](https://github.com/Dado1513/motan/tree/master/src/motan/ios_vulnerabilities/encryption_missing)
> The binary is not encrypted.

### [insecure_api](https://github.com/Dado1513/motan/tree/master/src/motan/ios_vulnerabilities/insecure_api)
> Binary makes use of insecure API(s).

### [insecure_connection_plist](https://github.com/Dado1513/motan/tree/master/src/motan/ios_vulnerabilities/insecure_connection_plist)
> The application adds exceptions for possible insecure connections in `Info.plist` file.

### [insecure_random](https://github.com/Dado1513/motan/tree/master/src/motan/ios_vulnerabilities/insecure_random)
> Binary makes use of some insecure random API(s).

### [insecure_tls_version_plist](https://github.com/Dado1513/motan/tree/master/src/motan/ios_vulnerabilities/insecure_tls_version_plist)
> The application sets the minimum value of TLS version TLSv1.0 or TLSv1.1, which are unsafe.

### [logging_function](https://github.com/Dado1513/motan/tree/master/src/motan/ios_vulnerabilities/logging_function)
> Binary makes use of logging function(s).

### [malloc_function](https://github.com/Dado1513/motan/tree/master/src/motan/ios_vulnerabilities/malloc_function)
> The binary may use `malloc` function.

### [no_forward_secrecy_plist](https://github.com/Dado1513/motan/tree/master/src/motan/ios_vulnerabilities/no_forward_secrecy_plist)
> The application disables the requirement that the server must support Perfect Forward Secrecy (PFS) through Elliptic Curve Diffie-Hellman Ephemeral (ECDHE).

### [nx_bit_missing](https://github.com/Dado1513/motan/tree/master/src/motan/ios_vulnerabilities/nx_bit_missing)
> The binary does not have NX bit set. NX bit offers protection against exploitation of memory corruption vulnerabilities by marking memory page as non-executable. 
> However, iOS never allows an app to execute from writeable memory. You do not need to specifically enable the NX bit because it's always enabled for all third-party code.

### [pie_flag_missing](https://github.com/Dado1513/motan/tree/master/src/motan/ios_vulnerabilities/pie_flag_missing)
> The binary is built without Position Independent Code flag. 
> In order to prevent an attacker from reliably jumping to, for example, a particular exploited function in memory, Address space layout randomization (ASLR) randomly arranges the address space positions of key data areas of a process, including the base of the executable and the positions of the stack,heap and libraries.

### [restricted_segment_missing](https://github.com/Dado1513/motan/tree/master/src/motan/ios_vulnerabilities/restricted_segment_missing)
> This binary does not have restricted segment that prevents dynamic loading of dylib for arbitrary code injection.

### [rpath_set](https://github.com/Dado1513/motan/tree/master/src/motan/ios_vulnerabilities/rpath_set)
> The binary has Runpath Search Path (@rpath) set. In certain cases an attacker can abuse this feature to run arbitrary executable for code execution and privilege escalation.

### [stack_canary_missing](https://github.com/Dado1513/motan/tree/master/src/motan/ios_vulnerabilities/stack_canary_missing)
> This binary does not have a stack canary value added to the stack. Stack canaries are used to detect and prevent exploits from overwriting return address.

### [symbols_stripped](https://github.com/Dado1513/motan/tree/master/src/motan/ios_vulnerabilities/symbols_stripped)
> Symbols are available.

### [weak_crypto](https://github.com/Dado1513/motan/tree/master/src/motan/ios_vulnerabilities/weak_crypto)
> Binary makes use of some weak crypto API(s).

### [weak_hashes](https://github.com/Dado1513/motan/tree/master/src/motan/ios_vulnerabilities/weak_hashes)
> Binary makes use of some weak hashing API(s).


## ❱ Contributing

Questions, bug reports and pull requests are welcome on GitHub at [https://github.com/Dado1513/motan](https://github.com/Dado1513/motan).



## ❱ License

*TBD*



## ❱ Team

* [Davide Caputo](https://csec.it/people/davide_caputo/) - Research Assistant & Developer
* [Gabriel Claudiu Georgiu](https://github.com/ClaudiuGeorgiu) - Developer
