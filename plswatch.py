#!/usr/bin/env python
#
# PulseChain Watch
#
# Shows swaps and new LP pairs created across Univ2 DEXes on PulseChain
#
# Forked from https://github.com/tradingstrategy-ai/web3-ethereum-defi/blob/master/scripts/uniswap-v2-swaps-live.py
#
# How to use it
#
# $ ./plswatch.py
# (see TXs for all tokens)
#
# $ ./plswatch.py HEX
#
# SWAP 324389.02 WPLS -> 1658.56 HEX [ 0x73c2e2856a5e2f98f392d5549d247eb7e18bbd86012fa18157417568aa729811 ]
# SWAP 313348.56 DAI -> 10003.82 HEX [ 0x73c2e2856a5e2f98f392d5549d247eb7e18bbd86012fa18157417568aa729811 ]
# SWAP 10003.82 HEX -> 1946241.79 WPLS [ 0x73c2e2856a5e2f98f392d5549d247eb7e18bbd86012fa18157417568aa729811 ]
# SWAP 560.72 HEX -> 7.62 INC [ 0x51c97d794340e5433d082049f69fef5df03719106a9550eb5ed645789113821e ]
# ...
#
# Setup
# - sudo apt install python-is-python3 -y
# - pip install "web3-ethereum-defi[data]" tqdm
#
# @rhmaximalist
#

import datetime
import os
import time
from functools import lru_cache
from pathlib import Path
import logging
import signal
import sys
import os

import requests
from tqdm import tqdm

from web3 import HTTPProvider, Web3

from eth_defi.abi import get_contract
from eth_defi.chain import install_chain_middleware, install_retry_middleware, install_api_call_counter_middleware
from eth_defi.event_reader.block_time import measure_block_time
from eth_defi.event_reader.conversion import decode_data, convert_int256_bytes_to_int, convert_jsonrpc_value_to_int
from eth_defi.event_reader.csv_block_data_store import CSVDatasetBlockDataStore
from eth_defi.event_reader.fast_json_rpc import patch_web3
from eth_defi.event_reader.reader import read_events, LogResult, prepare_filter
from eth_defi.event_reader.reorganisation_monitor import ChainReorganisationDetected, JSONRPCReorganisationMonitor
from eth_defi.uniswap_v2.pair import PairDetails, fetch_pair_details

logger = logging.getLogger(__name__)

# network configuration
PULSECHAIN_RPC = "https://rpc.pulsechain.com"
#PULSECHAIN_GAMMA_RPC = "https://rpc-pulsechain.g4mm4.io"
#PULSECHAIN_RPC = PULSECHAIN_GAMMA_RPC

# web configuration
WEB_MODE = False
PULSECHAIN_SCAN_TX_URL = "https://scan.pulsechain.com/tx/"

class AutoFlushHandler(logging.StreamHandler):
    def emit(self, record):
        super().emit(record)
        self.flush()

def stop(signum, frame):
    signal.signal(signal.SIGINT, signal.getsignal(signal.SIGINT))
    print(os.linesep)
    sys.exit(0)

@lru_cache(maxsize=None)
def fetch_pair_details_cached(web3: Web3, pair_address: str) -> PairDetails:
    """In-process memory cache for getting pair data in decoded format."""
    return fetch_pair_details(web3, pair_address)

# simple way to pull out TX hash for pair/LP events
# format sample
# {'address': '0x29ea7545def87022badc76323f373ea1e707c523', 'topics': ['0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9', '0x000000000000000000000000a1077a294dde1b09bb078844df40758a5d0f9a27', '0x000000000000000000000000b9c3464438d7050a1c61d50423714f9c2d49f980'], 'data': '0x000000000000000000000000b9ff28f14c12ad9edbca668cc61bb82a5fea63c20000000000000000000000000000000000000000000000000000000000005c97', 'blockNumber': 18685822, 'transactionHash': '0x3f2a6b4c124ee79fd68363fb2b7984efd41a17d56842efbb1ae2aae09c792fe4', 'transactionIndex': '0x23', 'blockHash': '0xaee88595e81a8bca8e08a2c3b975131c4eab7b4646b9ebdd719f4202d718eefc', 'logIndex': '0x8f', 'removed': False, 'context': None, 'event': <class 'web3._utils.datatypes.PairCreated'>, 'chunk_id': 18685812, 'timestamp': 1698498145}
def decode_pair(web3: Web3, log: LogResult) -> str:
    tx = log['transactionHash']
    return tx

def decode_swap(web3: Web3, log: LogResult) -> dict:
    """Process swap event.

    This function does manually optimised high speed decoding of the event.

    The event signature is:

    .. code-block::

        event Swap(
          address indexed sender,
          uint amount0In,
          uint amount1In,
          uint amount0Out,
          uint amount1Out,
          address indexed to
        );
    """

    # Raw example event
    # {'address': '0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc', 'blockHash': '0x4ba33a650f9e3d8430f94b61a382e60490ec7a06c2f4441ecf225858ec748b78', 'blockNumber': '0x98b7f6', 'data': '0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000046ec814a2e900000000000000000000000000000000000000000000000000000000000003e80000000000000000000000000000000000000000000000000000000000000000', 'logIndex': '0x4', 'removed': False, 'topics': ['0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822', '0x000000000000000000000000f164fc0ec4e93095b804a4795bbe1e041497b92a', '0x0000000000000000000000008688a84fcfd84d8f78020d0fc0b35987cc58911f'], 'transactionHash': '0x932cb88306450d481a0e43365a3ed832625b68f036e9887684ef6da594891366', 'transactionIndex': '0x1', 'context': <__main__.TokenCache object at 0x104ab7e20>, 'event': <class 'web3._utils.datatypes.Swap'>, 'timestamp': 1588712972}

    block_time = datetime.datetime.utcfromtimestamp(log["timestamp"])

    pair_contract_address = log["address"]

    pair_details = fetch_pair_details_cached(web3, pair_contract_address)

    # Optimised decode path for Uniswap v2 event data
    amount0_in, amount1_in, amount0_out, amount1_out = decode_data(log["data"])

    data = {
        "block_number": convert_jsonrpc_value_to_int(log["blockNumber"]),
        "timestamp": block_time.isoformat(),
        "tx_hash": log["transactionHash"],
        "log_index": int(log["logIndex"], 16),
        "pair_contract_address": pair_contract_address,
        "amount0_in": convert_int256_bytes_to_int(amount0_in),
        "amount1_in": convert_int256_bytes_to_int(amount1_in),
        "amount0_out": convert_int256_bytes_to_int(amount0_out),
        "amount1_out": convert_int256_bytes_to_int(amount1_out),
        "pair_details": pair_details,
    }
    return data

def format_swap(swap: dict, token: str) -> str:
    pair: PairDetails = swap["pair_details"]
    token0 = pair.token0
    token1 = pair.token1
    tx_hash = swap["tx_hash"]
    #block_number = swap["block_number"]

    if(token0.symbol == None):
        token0.symbol = 'Unknown'

    if(token1.symbol == None):
        token1.symbol = 'Unknown'

    if swap["amount0_in"] and not swap["amount1_in"]:
        token_in = token0
        token_out = token1
        amount_in = token0.convert_to_decimals(swap["amount0_in"])
        amount_out = token1.convert_to_decimals(swap["amount1_out"])

        if(WEB_MODE):
            output = f"SWAP {amount_in:.2f} {token_in.symbol} -> {amount_out:.2f} {token_out.symbol} [ <a href=\"{PULSECHAIN_SCAN_TX_URL}{tx_hash}\" target=\"_blank\">{tx_hash}</a> ]"
        else:
            output = f"SWAP {amount_in:.2f} {token_in.symbol} -> {amount_out:.2f} {token_out.symbol} [ {tx_hash} ]"

        if(token == None):
            return output
        else:
            if(token in token_in.symbol or token in token_out.symbol):
                return output
            else:
                return ""
    elif swap["amount1_in"] and not swap["amount0_in"]:
        token_in = token1
        token_out = token0
        amount_in = token1.convert_to_decimals(swap["amount1_in"])
        amount_out = token0.convert_to_decimals(swap["amount0_out"])

        if(WEB_MODE):
            output = f"SWAP {amount_in:.2f} {token_in.symbol} -> {amount_out:.2f} {token_out.symbol} [ <a href=\"{PULSECHAIN_SCAN_TX_URL}{tx_hash}\" target=\"_blank\">{tx_hash}</a> ]"
        else:
            output = f"SWAP {amount_in:.2f} {token_in.symbol} -> {amount_out:.2f} {token_out.symbol} [ {tx_hash} ]"

        if(token == None):
            return output
        else:
            if(token in token_in.symbol or token in token_out.symbol):
                return output
            else:
                return ""
    else:
        amount0_in = token0.convert_to_decimals(swap["amount0_in"])
        amount1_in = token1.convert_to_decimals(swap["amount1_in"])
        amount0_out = token0.convert_to_decimals(swap["amount0_out"])
        amount1_out = token1.convert_to_decimals(swap["amount1_out"])

        if(WEB_MODE):
            output = f"SWAP {amount0_in:.2f} {token0.symbol}, {amount1_in:.2f} {token1.symbol} -> {amount0_out:.2f} {token0.symbol}, {amount1_out:.2f} {token1.symbol} [ <a href=\"{PULSECHAIN_SCAN_TX_URL}{tx_hash}\" target=\"_blank\">{tx_hash}</a> ]"
        else:
            output = f"SWAP {amount0_in:.2f} {token0.symbol}, {amount1_in:.2f} {token1.symbol} -> {amount0_out:.2f} {token0.symbol}, {amount1_out:.2f} {token1.symbol} [ {tx_hash} ]"


        if(token == None):
            return output
        else:
            if(token in token0.symbol or token in token1.symbol):
                return output
            else:
                return ""

def setup_logging():
    level = os.environ.get("LOG_LEVEL", "info").upper()

    fmt = "%(message)s"
    date_fmt = "%H:%M:%S"

    logging.basicConfig(level=level, handlers=[AutoFlushHandler(sys.stdout)], format=fmt)

    # Mute noise
    logging.getLogger("web3.providers.HTTPProvider").setLevel(logging.WARNING)
    logging.getLogger("web3.RequestManager").setLevel(logging.WARNING)
    logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)

def main():
    # if no token is specified, show everything
    if(len(sys.argv) != 2):
        token = None
    else:
        token = sys.argv[1]

    # start fresh each time (may be related to bug that keeps the app from working right over time)
    if(os.path.exists("uni-v2-last-block-state.csv")):
        os.remove("uni-v2-last-block-state.csv")

    # catch ctrl+c
    signal.signal(signal.SIGINT, stop)

    # mute extra logging output
    setup_logging()

    # HTTP 1.1 keep-alive to speed up JSON-RPC protocol
    session = requests.Session()

    json_rpc_url = os.environ.get("JSON_RPC_PULSECHAIN", PULSECHAIN_RPC)
    web3 = Web3(HTTPProvider(json_rpc_url, session=session))

    # Enable faster JSON decoding with ujson
    patch_web3(web3)

    web3.middleware_onion.clear()

    # Setup Polygon middleware support
    install_chain_middleware(web3)

    # Setup support for retry after JSON-RPC endpoint starts throttling us
    install_retry_middleware(web3)

    # Count API requests
    api_request_counter = install_api_call_counter_middleware(web3)

    # Get contracts
    Factory = get_contract(web3, "sushi/UniswapV2Factory.json") # factory events
    Pair = get_contract(web3, "sushi/UniswapV2Pair.json") # pair events

    # Create a filter that will match both PairCreated and Swap events
    # when reading tx receipts
    # could also explore/parse events such as Pair.events.Mint and others
    # https://github.com/tradingstrategy-ai/web3-ethereum-defi/blob/f73e3efcd53f5ed0e59a302ae5b6ccbd3c20e8c3/eth_defi/abi/sushi/UniswapV2Pair.json
    filter = prepare_filter([Factory.events.PairCreated, Pair.events.Swap])

    # Store block headers locally in a CSV file,
    # so we can speed up startup
    block_store = CSVDatasetBlockDataStore(Path("uni-v2-last-block-state.csv"))

    # Create a blockchain minor reorganisation detector,
    # so we can handle cases when the last block is rolled back
    reorg_mon = JSONRPCReorganisationMonitor(web3)

    if not block_store.is_virgin():
        # Start from the existing save point
        block_header_df = block_store.load()
        reorg_mon.load_pandas(block_header_df)
        #logger.info("Loaded %d existing blocks from %s.\n" "If the save checkpoint was long time ago, we need to catch up all blocks and it could be slow.", len(block_header_df), block_store.path)
    else:
        # Start from the scratch,
        # use tqdm progess bar for interactive progress
        initial_block_count = 50
        #logger.info("Starting with fresh block header store at %s, cold start fetching %d blocks", block_store.path, initial_block_count)
        reorg_mon.load_initial_block_headers(initial_block_count, tqdm=tqdm)

    # Block time can be between 3 seconds to 12 seconds depending on
    # the EVM chain
    #block_time = measure_block_time(web3)
    block_time = 10 # PulseChain

    total_reorgs = 0

    stat_delay = 10
    next_stat_print = time.time() + stat_delay

    while True:
        try:
            # Figure out the next good unscanned block range,
            # and fetch block headers and timestamps for this block range
            chain_reorg_resolution = reorg_mon.update_chain()

            #if chain_reorg_resolution.reorg_detected:
            #    logger.info(f"Chain reorganisation data updated: {chain_reorg_resolution}")

            # Read specified events in block range
            for log_result in read_events(
                web3,
                start_block=chain_reorg_resolution.latest_block_with_good_data + 1,
                end_block=chain_reorg_resolution.last_live_block,
                filter=filter,
                notify=None,
                chunk_size=100,
                extract_timestamps=None,
                reorg_mon=reorg_mon,
            ):
                if log_result["event"].event_name == "PairCreated":
                    #logger.info(f"\nNew pair or created: {log_result}\n")
                    if(token == None):
                        #logger.info(f"\nNew pair or LP event: {log_result}\n")
                        tx = decode_pair(web3, log_result)
                        if(WEB_MODE):
                            logger.info(f"\nNEW PAIR OR LIQUIDITY EVENT: [ <a href=\"{PULSECHAIN_SCAN_TX_URL}{tx}\" target=\"_blank\">{tx}</a> ]\n")
                        else:
                            logger.info(f"\nNEW PAIR OR LIQUIDITY EVENT: TX {tx}\n")
                elif log_result["event"].event_name == "Swap":
                    swap = decode_swap(web3, log_result)
                    swap_fmt = format_swap(swap, token)
                    if(len(swap_fmt) > 2): # don't print empty lines
                        logger.info("%s", swap_fmt)
                else:
                    raise NotImplementedError()

            # Dump stats to the output regularly
            if time.time() > next_stat_print:
                req_count = api_request_counter["total"]
                #logger.info("**STATS** Reorgs detected: %d, block headers buffered: %d, API requests made: %d", total_reorgs, len(reorg_mon.block_map), req_count)
                next_stat_print = time.time() + stat_delay

                # Save the current block headers on disk
                # to speed up the next start
                df = reorg_mon.to_pandas()
                block_store.save(df)

        except ChainReorganisationDetected as e:
            # Chain reorganisation was detected during reading the events.
            # reorg_mon.update_chain() will detect the fork and purge bad state
            total_reorgs += 1
            #logger.warning("Chain reorg event raised: %s, we have now detected %d chain reorganisations.", e, total_reorgs)

        time.sleep(block_time)

if __name__ == "__main__":
    main()
