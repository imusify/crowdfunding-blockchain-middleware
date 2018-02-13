#!/usr/bin/env python3
"""
Imusify crowdfunding blockchain middleware

Example usage (with "123" as valid API token):

    NEO_REST_API_TOKEN="123" ./imusify-crowdfunding-api/api.py

Example API calls:

    # Create a wallet
    $ curl -vvv -X POST -H "Authorization: Bearer 123" -d '{ "password": "testpwd123" }' localhost:8080/wallets/create

    # Get IMU balance
    $ curl -vvv -X GET -H "Authorization: Bearer 123" localhost:8080/imuBalance/AKadKVhU43qfaLW3JGmK9MoAJ4VNp1oCdu

    # Create a crowdfunding
    $ curl -vvv -X POST -H "Authorization: Bearer 123" -d '{ "memberAddresses": [] }' localhost:8080/crowdfunding/create

"""
import os
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


# Set the hash of your contract here:
SMART_CONTRACT_HASH = "6537b4bd100e514119e3a7ab49d520d20ef2c2a4"

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

# Internal: setup the smart contract instance
smart_contract = SmartContract(SMART_CONTRACT_HASH)

# Internal: setup the klein instance
app = Klein()

# Internal: generate the @authenticated decorator with valid tokens
authenticated = gen_authenticated_decorator(API_AUTH_TOKEN)

#
# Smart contract event handler for Runtime.Notify events
#


@smart_contract.on_notify
def sc_notify(event):
    logger.info("SmartContract Runtime.Notify event: %s", event)

    # Make sure that the event payload list has at least one element.
    if not len(event.event_payload):
        return

    # The event payload list has at least one element. As developer of the smart contract
    # you should know what data-type is in the bytes, and how to decode it. In this example,
    # it's just a string, so we decode it with utf-8:
    logger.info("- payload part 1: %s", event.event_payload[0].decode("utf-8"))


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
@app.route('/')
def home(request):
    return "Hello world"


@app.route('/echo/<msg>')
@catch_exceptions
@authenticated
@json_response
def echo_msg(request, msg):
    return {
        "echo": msg
    }


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

    return {
        "balanceImu": "0.0"
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
    # Setup the blockchain
    blockchain = LevelDBBlockchain(settings.LEVELDB_PATH)
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

    # Hook up Klein API to Twisted reactor
    endpoint_description = "tcp:port=%s:interface=localhost" % API_PORT
    endpoint = endpoints.serverFromString(reactor, endpoint_description)
    endpoint.listen(Site(app.resource()))

    # Run all the things (blocking call)
    logger.info("Everything setup and running. Waiting for events...")
    reactor.run()
    logger.info("Shutting down.")


if __name__ == "__main__":
    main()
