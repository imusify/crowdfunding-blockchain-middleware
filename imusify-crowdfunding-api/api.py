#!/usr/bin/env python3
"""
Imusify crowdfunding blockchain middleware

Example usage (with "123" as valid API token):

    NEO_REST_API_TOKEN="123" ./imusify-crowdfunding-api/api.py

Example API calls:

    # Test
    $ curl -vvv -H "Authorization: Bearer 123" localhost:8080/test

    # Create a wallet
    $ curl -vvv -X POST -H "Authorization: Bearer 123" -d '{ "password": "testpwd123" }' localhost:8080/wallets/create

    # Get IMU balance
    $ curl -vvv -X GET -H "Authorization: Bearer 123" localhost:8080/imuBalance/AK2nJJpJr6o664CWJKi1QRXjqeic2zRp8y

    # Create a crowdfunding
    $ curl -vvv -X POST -H "Authorization: Bearer 123" -d '{ "memberAddresses": [] }' localhost:8080/crowdfunding/create

"""
import os
import argparse
import threading
import json
from time import sleep
from Crypto import Random

from logzero import logger
from twisted.internet import reactor, task, endpoints
from twisted.web.server import Request, Site
from klein import Klein, resource

from neo.Network.NodeLeader import NodeLeader
from neo.Core.Blockchain import Blockchain
from neo.Implementations.Blockchains.LevelDB.LevelDBBlockchain import LevelDBBlockchain
from neo.Settings import settings

from neo.Network.api.decorators import json_response, gen_authenticated_decorator, catch_exceptions
from neo.contrib.smartcontract import SmartContract

from neocore.KeyPair import KeyPair
from imusmartcontract import ImuSmartContract


# Set the hash of your contract here:
SMART_CONTRACT_HASH = "95ed79af690e274ad6c5594c4496daf72f5832b6"

# Default REST API port is 8080, and can be overwritten with an env var:
API_PORT = os.getenv("NEO_REST_API_PORT", 8080)

# If you want to enable logging to a file, set the filename here:
LOGFILE = os.getenv("NEO_REST_LOGFILE", None)

# Internal: if LOGFILE is set, file logging will be setup with max
# 10 MB per file and 3 rotations:
if LOGFILE:
    settings.set_logfile(LOGFILE, max_bytes=1e7, backup_count=3)

# Internal: get the API token from an environment variable
API_AUTH_TOKEN = os.getenv("NEO_REST_API_TOKEN", None)
if not API_AUTH_TOKEN:
    raise Exception("No NEO_REST_API_TOKEN environment variable found!")

imuSmartContract = ImuSmartContract(SMART_CONTRACT_HASH, "neo-privnet.wallet", "coz")

# Internal: setup the klein instance
app = Klein()

# Internal: generate the @authenticated decorator with valid tokens
authenticated = gen_authenticated_decorator(API_AUTH_TOKEN)

#
# Custom code that runs in the background
#
def custom_background_code():
    """ Custom code run in a background thread. Prints the current block height.

    This function is run in a daemonized thread, which means it can be instantly killed at any
    moment, whenever the main thread quits. If you need more safety, don't use a  daemonized
    thread and handle exiting this thread in another way (eg. with signals and events).
    """
    while True:
        logger.info("Block %s / %s", str(Blockchain.Default().Height), str(Blockchain.Default().HeaderHeight))
        sleep(15)


# API error codes
STATUS_ERROR_AUTH_TOKEN = 1
STATUS_ERROR_JSON = 2
STATUS_ERROR_GENERIC = 3


def build_error(error_code, error_message, to_json=True):
    """ Builder for generic errors """
    res = {
        "errorCode": error_code,
        "errorMessage": error_message
    }
    return json.dumps(res) if to_json else res


#
# REST API Routes
#
@app.route('/test')
def home(request):
    results = imuSmartContract.read_only_invoke("circulation")
    circulation = results[0].GetBigInteger()
    logger.info("circulation: %s", circulation)
    return "Hello world"


@app.route('/wallets/create', methods=['POST'])
@catch_exceptions
@authenticated
@json_response
def create_wallet(request):
    try:
        body = json.loads(request.content.read().decode("utf-8"))
    except JSONDecodeError as e:
        request.setResponseCode(400)
        return build_error(STATUS_ERROR_JSON, "JSON Error: %s" % str(e))

    # Fail if not a password
    if not "password" in body:
        request.setResponseCode(400)
        return build_error(STATUS_ERROR_JSON, "No password in request body.")

    # Fail if no good password
    pwd = body["password"]
    if len(pwd) < 8:
        request.setResponseCode(400)
        return build_error(STATUS_ERROR_JSON, "Password needs a minimum length of 8 characters.")

    private_key = bytes(Random.get_random_bytes(32))
    key = KeyPair(priv_key=private_key)

    return {
        "address": key.GetAddress(),
        "nep2_key": key.ExportNEP2(pwd)
    }


@app.route('/imuBalance/<address>')
@catch_exceptions
@authenticated
@json_response
def get_imu_balance(request, address):
    if len(address) != 34:
        logger.warn("Wallet address '%s' is not 34 characters" % address)
        request.setResponseCode(400)
        return build_error(STATUS_ERROR_JSON, "Address not 34 characters")

    results = imuSmartContract.read_only_invoke("balanceOf", address)
    balance = results[0].GetBigInteger()
    logger.info("balance: %s", balance)

    return {
        "balanceImu": balance
    }


@app.route('/crowdfunding/create', methods=['POST'])
@catch_exceptions
@authenticated
@json_response
def create_crowdfunding(request):
    try:
        body = json.loads(request.content.read().decode("utf-8"))
    except JSONDecodeError as e:
        request.setResponseCode(400)
        return build_error(STATUS_ERROR_JSON, "JSON Error: %s" % str(e))

    # Fail if not a password
    if not "memberAddresses" in body:
        request.setResponseCode(400)
        return build_error(STATUS_ERROR_JSON, "No memberAddresses in request body.")

    # Fail if no good password
    memberAddresses = body["memberAddresses"]
    # print(memberAddresses, type(memberAddresses))
    if not isinstance(memberAddresses, list):
        request.setResponseCode(400)
        return build_error(STATUS_ERROR_JSON, "memberAddresses needs to be a list.")

    if len(memberAddresses) < 1 or len(memberAddresses) > 4:
        request.setResponseCode(400)
        return build_error(STATUS_ERROR_JSON, "1-4 memberAddresses are allowed")

    # Check all memberAddresses
    for address in memberAddresses:
        if len(address) != 34:
            request.setResponseCode(400)
            return build_error(STATUS_ERROR_JSON, "Address not 34 characters")

    # TODO: put into queue, invoke smart contract. this is only a mock response
    return {
        "crowdfundingAddress": "AKadKVhU43qfaLW3JGmK9MoAJ4VNp1oCdu"
    }


#
# Main method which starts everything up
#
def main():
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-m", "--mainnet", action="store_true", default=False,
                       help="Use MainNet instead of the default TestNet")
    group.add_argument("-p", "--privnet", action="store_true", default=False,
                       help="Use PrivNet instead of the default TestNet")
    group.add_argument("--coznet", action="store_true", default=False,
                       help="Use the CoZ network instead of the default TestNet")
    group.add_argument("-c", "--config", action="store", help="Use a specific config file")

    args = parser.parse_args()

    # Setup depending on command line arguments. By default, the testnet settings are already loaded.
    if args.config:
        settings.setup(args.config)
    elif args.mainnet:
        settings.setup_mainnet()
    elif args.privnet:
        settings.setup_privnet()
    elif args.coznet:
        settings.setup_coznet()

    # Setup the blockchain
    blockchain = LevelDBBlockchain(settings.LEVELDB_PATH)
    # logger.info(settings.LEVELDB_PATH)
    Blockchain.RegisterBlockchain(blockchain)
    dbloop = task.LoopingCall(Blockchain.Default().PersistBlocks)
    dbloop.start(.1)
    NodeLeader.Instance().Start()

    # Disable smart contract events for external smart contracts
    settings.set_log_smart_contract_events(False)
    logger.info("Using network: %s" % settings.net_name)

    # Start a thread with custom code
    d = threading.Thread(target=custom_background_code)
    d.setDaemon(True)  # daemonizing the thread will kill it when the main thread is quit
    d.start()

    # Start ImuSmartContract thread
    imuSmartContract.start()

    # Hook up Klein API to Twisted reactor
    endpoint_description = "tcp:port=%s" % API_PORT
    endpoint = endpoints.serverFromString(reactor, endpoint_description)
    endpoint.listen(Site(app.resource()))

    # Run all the things (blocking call)
    logger.info("Everything setup and running. Waiting for events...")
    reactor.run()
    logger.info("Shutting down.")


if __name__ == "__main__":
    main()
