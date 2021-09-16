# Aries Cloud Agent - Python Plugin for MyData DID DIDComm protcol


<p align="center">
    <a href="/../../commits/" title="Last Commit"><img src="https://img.shields.io/github/last-commit/decentralised-dataexchange/automated-data-agreements?style=flat"></a>
    <a href="/../../issues" title="Open Issues"><img src="https://img.shields.io/github/issues/decentralised-dataexchange/automated-data-agreements?style=flat"></a>
    <a href="./LICENSE" title="License"><img src="https://img.shields.io/badge/License-Apache%202.0-green.svg?style=flat"></a>
</p>


<p align="center">
  <a href="#about">About</a> •
  <a href="#installation">Installation</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#licensing">Licensing</a>
</p>


## About

This repository contains the opensource for ACA-Py plugin for Data Agreement released as part of the Automated Data Agreement (ADA) Project. This is part of NGI-eSSIF-Lab project that has received funding from the European Union’s Horizon 2020 research and innovation programme under grant agreement No 871932.

## ACA-Py Version Compatibility

To avoid a confusing pseudo-lock-step release, this plugin is
versioned independent of ACA-Py. Plugin releases will follow standard
[semver](semver.org) but each release will also be tagged with a mapping to an
ACA-Py version with the format `acapy-X.Y.Z-J` where `X.Y.Z` corresponds to the
ACA-Py version supported and `J` is an incrementing number for each new plugin
release that targets the same version of ACA-Py.

You should look for the most recent release tagged with the version of ACA-Py
you are using (with the highest value for `J`).

## Installation

Requirements:
- Python 3.6 or higher
- ACA-Py

### Setup Aries Cloud Agent - Python

If you already have an existing installation of ACA-Py, you can skip these steps
and move on to [plugin installation](#plugin-installation). It is also worth
noting that this is not the only way to setup an ACA-Py instance. For more setup
configurations, see the [Aries Cloud Agent - Python
repository](https://github.com/hyperledger/aries-cloudagent-python).

First, clone
[ACA-Py](https://github.com/hyperledger/aries-cloudagent-python) and prepare a
virtual environment:
```sh
$ git clone https://github.com/hyperledger/aries-cloudagent-python
$ cd aries-cloudagent-python
$ python3 -m venv env
$ source env/bin/activate
```

Install ACA-Py into the virtual environment:
```sh
$ pip install -e .
```
**Or** include the `indy` feature if you want to use Indy ledgers or wallets:
```sh
$ pip install -e .[indy]
```

### Plugin Installation

Install this plugin into the virtual environment:

```sh
$ pip install git+https://github.com/decentralised-dataexchange/acapy-mydata-did-protocol.git@master#egg=mydata_did
```

**Note:** Depending on your version of `pip`, you may need to drop the
`#egg=...` to install the plugin with the above command.

### Plugin Loading
Start up ACA-Py with the plugin parameter:
```sh
$ aca-py start \
    -it http localhost 3000 -it ws localhost 3001 \
    -ot http \
    -e http://localhost:3000 ws://localhost:3001 \
    --plugin "mydata_did"
```

## Contributing

Feel free to improve the plugin and send us a pull request. If you found any problems, please create an issue in this repo.

## Licensing
Copyright (c) 2021-22 LCubed AB (iGrant.io), Sweden

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

You may obtain a copy of the License at https://www.apache.org/licenses/LICENSE-2.0.

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the LICENSE for the specific language governing permissions and limitations under the License.