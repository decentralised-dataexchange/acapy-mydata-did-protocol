# ACA-Py plugin for MyData DID DIDComm protcol

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
$ pip install git+https://github.com/decentralised-dataexchange/acapy-mydata-did-protocol.git@master
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