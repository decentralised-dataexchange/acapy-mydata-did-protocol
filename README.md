# ACA-Py plugin for MyData DID DIDComm protcol

## Acknowledgements

This repository was originally created as as a deliverable for Automated Data Agreement (ADA) Project. ADA project is part of NGI-eSSIF-Lab project that has received funding from the European Union’s Horizon 2020 research and innovation programme under grant agreement No 871932.

The lead developer to this project is iGrant.io (Sweden), supported by Linaltec (Sweden) and PrivacyAnt (Finland).

## ACA-Py Version Compatibility

This plugin is compatible with ACA-Py version 0.5.6.

## Installation

Requirements:
- Python 3.6 or higher
- ACA-Py 0.5.6

### Setup Aries Cloud Agent - Python

If you already have an existing installation of ACA-Py, you can skip these steps
and move on to [plugin installation](#plugin-installation). It is also worth
noting that this is not the only way to setup an ACA-Py instance. For more setup
configurations, see the [Aries Cloud Agent - Python
repository](https://github.com/hyperledger/aries-cloudagent-python).

First, prepare a virtual environment:
```sh
$ python3 -m venv env
$ source env/bin/activate
```

Install ACA-Py 0.5.6 into the virtual environment:
```sh
$ pip install aries-cloudagent==0.5.6
```

### Plugin Installation

Install this plugin into the virtual environment:

```sh
$ pip install acapy-mydata-did-protocol
```

**Note:** Depending on your version of `pip`, you may need to drop or add 
`#egg=mydata_did` to install the plugin with the above command.

### Plugin Loading
Start up ACA-Py with the plugin parameter:
```sh
$ aca-py start \
    -it http 0.0.0.0 8002 \
    -ot http \
    -e "http://localhost:8002/" \
    --label "Agent" \
    --admin 0.0.0.0 8001 \
    --admin-insecure-mode \
    --auto-accept-requests \
    --auto-ping-connection \
    --auto-respond-credential-offer \
    --auto-respond-credential-request \
    --auto-store-credential \
    --auto-respond-presentation-proposal \
    --auto-respond-presentation-request \
    --auto-verify-presentation \
    --genesis-url https://indy.igrant.io/genesis \
    --wallet-type indy \
    --wallet-name "agent_wallet" \
    --log-level info \
    --wallet-key "wallet@123" \
    --plugin "mydata_did"
```

## Licensing

Copyright (c) 2021-23 LCubed AB (iGrant.io), Sweden

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

You may obtain a copy of the License at https://www.apache.org/licenses/LICENSE-2.0.

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the LICENSE for the specific language governing permissions and limitations under the License.
