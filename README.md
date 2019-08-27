# CertAutomator
---
## Description
A script that automates the generation of self-signed CA's and users keys, certificate requests and signed certificates for test environments.

## Setup

* Clone or download the script files.
* Generate a [configuration file](https://github.com/chrisl84/certautomator/blob/master/config_file_description) as outlined in the link.
* Run the python script using the parameters as described below.

The script gathers and parses the information in the config file, then generates directory structures for the keys and certificates. 
After the information has been processed, the script uses the openssl library to generate keys and certificates for the CA (if one is specified) and then keys and certificates for any additional users. 
Signing is done using the specified CA. 
Though more than one CA can be specified for each group, the script will only use the last CA to sign certificate requests from the users. See [TODO](#todo) for information on work in progress. 

## Script parameters

-h : Shows the command line arguments.

--verbose / -v : Logs debug messages.

--quiet / -q : Logs warning messages only.

--config : Location of the JSON configuration file, defaults to ./config.json.

--log : Location of the log file, defaults to ./openssltoolslib.log.

--openssl : Location of the openssl binaries, defaults to /usr/bin/openssl.

--overwrite : Will overwrite keys, requests or certificates if they already exists.
-! **(WARNING: This will overwrite all files and directories without prompting. Use with caution)** !-

--all / -a : Generates keys, requests and certificates (if CA is specified).

--key / -k : Generate keys only.

--req / -r : Generate certificate signing request (requires key to be present).

--sign / -s : Sign certificate signing request and generate certificate (requires request and CA to be present).

--group : Specify, using ',' separator, the groups to generate keys, signing requests and certificates for only.

--users : Specify, using ',' separator, the users to generate keys, signing requests and certificates for only.

## Requirements
* Script requires [openssl](https://www.openssl.org) binaries. 
* [Python 3.6](https://www.python.org/).

## Runs on:
* Linux/Ubuntu.

## GPLv3 License
* [GPLv3](http://www.gnu.org/licenses/).


## <a name="todo"></a>TODO:
* Add flag to specify which CA you would like to sign the certificates.
* Add flag to specify which users should be overwritten.
