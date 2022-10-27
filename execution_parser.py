"""This module parses the execution layer Block and related Transaction data."""
import datetime
import itertools
import json
from pathlib import Path
from typing import Mapping, NewType, Optional, Sequence, Tuple, Union

import jsonlines
import pendulum
from hexbytes import HexBytes
from pydantic import BaseModel, Field, conint, constr
from web3 import HTTPProvider, Web3

Wei = NewType("Wei", conint(strict=True, ge=0))
Gas = NewType("Gas", conint(strict=True, ge=0))
HexStr = NewType("HexStr", constr(regex=("^(0[xX])?[0-9a-fA-F]*$")))
BlockNumber = NewType("BlockNumber", conint(ge=0))
HexAddress = NewType("HexAddress", constr(regex="^0[xX][0-9a-fA-F]{40}$"))
Timestamp = NewType("Timestamp", conint(ge=1438214400))

CONSTANTINOPLE_BLOCK: BlockNumber = 7280000
CONSTANTINOPLE_BASE_REWARD: Wei = 3_000_000_000_000_000_000
PARIS_BLOCK: BlockNumber = 15537393
PARIS_BASE_REWARD: Wei = 2_000_000_000_000_000_000
NODE_ENDPOINT = "http://REPLACE_ME:8545"
START_BLOCK, END_BLOCK = 15_313_393, 15_761_393


class HexJSONEncoder(json.JSONEncoder):
    """Extends Elasticsearch JSON Serializer to add convertion of HexBytes to string."""

    def default(self, obj):
        """Extend default."""
        if isinstance(obj, HexBytes):
            return obj.hex()
        return super().default(obj)


class AccessListEntry(BaseModel):
    """AccessList transaction, EIP-2930."""

    address: HexStr
    storageKeys: Sequence[HexStr]  # = Field(..., alias="storage_keys")


class TransactionData(BaseModel):
    """Depending on the transaction type, it could be EIP-2718 (legacy) or EIP-2930."""

    transactionIndex: conint(ge=0)
    blockHash: HexBytes
    blockNumber: BlockNumber
    chainId: Optional[HexStr]
    from_field: HexAddress = Field(..., alias="from")
    to: Optional[HexAddress]
    value: Wei
    gas: Gas
    gasPrice: Wei
    maxFeePerGas: Optional[Wei]
    maxPriorityFeePerGas: Optional[Wei]
    hash: HexBytes  # noqa: A003
    data: Optional[Union[bytes, HexStr]]
    input: HexStr  # noqa: A003
    nonce: int
    type: Union[int, HexStr]  # noqa: A003
    r: HexBytes
    s: HexBytes
    v: int
    accessList: Optional[Sequence[AccessListEntry]]


class LogReceipt(BaseModel):
    """Log generated by the transaction."""

    address: Optional[HexAddress]
    blockHash: Optional[HexBytes]
    blockNumber: Optional[BlockNumber]
    data: Optional[HexStr]
    logIndex: Optional[conint(ge=0)]
    payload: Optional[HexBytes]
    removed: Optional[bool]
    topic: Optional[HexBytes]
    topics: Optional[Sequence[HexBytes]]
    transactionHash: HexBytes
    transactionIndex: Optional[conint(ge=0)]


class TransactionReceipt(BaseModel):
    """Depending on the transaction type, it could be EIP-2718 (legacy) or EIP-2930."""

    blockHash: HexBytes
    blockNumber: BlockNumber
    contractAddress: Optional[HexAddress]
    cumulativeGasUsed: Gas
    # The actual value per gas deducted from the senders account.
    # Before EIP-1559, this is equal to the transaction's gas price.
    # After, it is equal to baseFeePerGas + min(maxFeePerGas - baseFeePerGas, maxPriorityFeePerGas).
    effectiveGasPrice: Wei
    gasUsed: Gas
    from_field: HexAddress = Field(..., alias="from")
    logs: Sequence[LogReceipt]
    logsBloom: HexBytes
    # The post-transaction state root.
    # Only specified for transactions included before the Bysantium upgrade.
    root: Optional[HexStr]
    # Either 1 (sucess) or 0 (failure)
    # Only specified for transactions included after the Bysantium upgrade.
    status: Optional[bool]
    # Address of the receiver or null in a contract creation transaction.
    to: Optional[HexAddress]
    transactionHash: HexBytes
    transactionIndex: conint(ge=0)


class BlockData(BaseModel):
    """Information contained on a Block."""

    baseFeePerGas: Wei
    difficulty: conint(ge=0)
    extraData: HexBytes
    gasLimit: Gas
    gasUsed: Gas
    hash: HexBytes  # noqa: A003
    logsBloom: HexBytes
    miner: HexAddress
    mixHash: HexBytes
    nonce: HexBytes
    number: BlockNumber
    parentHash: HexBytes
    receiptsRoot: HexBytes
    sha3Uncles: HexBytes
    size: conint(ge=0)
    stateRoot: HexBytes
    timestamp: Timestamp
    totalDifficulty: conint(ge=0)
    transactions: Union[Sequence[HexBytes], Sequence[TransactionData]]
    transactionsRoot: HexBytes
    uncles: Sequence[HexBytes]


def _rename_keys(old_dict: Mapping, key_mapping: Mapping) -> dict:
    output = old_dict.copy()
    for old_key, new_key in key_mapping.items():
        if old_key in output:
            output[new_key] = output.pop(old_key)
    return output


class BlockExporter:
    """BlockExporter.

    Class use to parse the execution block data
    """

    FIELD_NAMES = {
        "baseFeePerGas": "base_fee_per_gas",
        "extraData": "extra_data",
        "gasLimit": "gas_limit",
        "gasUsed": "gas_used",
        "hash": "block_hash",
        "logsBloom": "logs_bloom",
        "mixHash": "mix_hash",
        "number": "block_number",
        "parentHash": "parent_hash",
        "receiptsRoot": "receipts_root",
        "sha3Uncles": "sha3_uncles",
        "stateRoot": "state_root",
        "totalDifficulty": "total_difficulty",
        "transactionsRoot": "transactions_root",
    }

    def parse(self, blk_data: BlockData) -> Tuple[list, dict]:
        """parse.

        :param blk_data: parsed response
        :return: List[Transactions], Output=Dict[str, Any]
        """
        txs_count: int = len(blk_data.transactions)
        burnt_fees: int = blk_data.gasUsed * blk_data.baseFeePerGas
        base_reward: int = 0
        if blk_data.number < CONSTANTINOPLE_BLOCK:
            base_reward = CONSTANTINOPLE_BASE_REWARD
        elif blk_data.number < PARIS_BLOCK:
            base_reward = PARIS_BASE_REWARD
        output = blk_data.dict(by_alias=True)
        output.pop("transactions", None)
        output |= {
            "id": f"block-{blk_data.number}",
            "data_type": "block",
            "transactions_count": txs_count,
            "burnt_fees": burnt_fees,
            "reward_base": base_reward,
            "@timestamp": pendulum.instance(
                datetime.datetime.fromtimestamp(blk_data.timestamp, tz=datetime.timezone.utc)
            ).format(r"YYYY-MM-DDTHH:mm:ss.SSS\Z"),
        }
        output = _rename_keys(output, self.FIELD_NAMES)
        return blk_data.transactions, output


class TransactionExporter:
    """TransactionExporter.

    Class use to parse the execution transaction data into the format required by the Database.
    """

    FIELD_NAMES = {
        "transactionIndex": "transaction_index",
        "blockHash": "block_hash",
        "blockNumber": "block_number",
        "chainId": "chain_id",
        "gasPrice": "gas_price",
        "maxFeePerGas": "max_fee_per_gas",
        "maxPriorityFeePerGas": "max_priority_fee_per_gas",
        "hash": "transaction_hash",
        "accessList": "access_list",
    }

    def parse(self, txs_data: Sequence[TransactionData]) -> Tuple[list, list[dict]]:
        """parse.

        :param txs_data: List of transactions
        :return: List[TransactionHash], Output=List[Dict[str,Any]]
        """
        tx_hashes = []
        output = []
        tx_total = len(txs_data) - 1
        for tx in txs_data:
            tx_hashes.append(tx.hash)
            out_ = tx.dict(by_alias=True)
            out_ |= {
                "id": f"transaction-{tx.blockNumber}-{tx.transactionIndex}",
                "data_type": "transaction",
                "transaction_last": tx.transactionIndex == tx_total,
            }
            out_ = _rename_keys(out_, self.FIELD_NAMES)
            output.append(out_)

        return tx_hashes, output


class TxReceiptExporter:
    """Transaction Receipt Exporter.

    Class use to parse the execution transaction receipt data into the format required by the Database.
    """

    FIELD_NAMES = {
        "transactionIndex": "transaction_index",
        "transactionHash": "transaction_hash",
        "blockHash": "block_hash",
        "blockNumber": "block_number",
        "cumulativeGasUsed": "cumulative_gas_used",
        "effectiveGasPrice": "effective_gas_price",
        "gasUsed": "gas_used",
        "logsBloom": "logs_bloom",
    }

    def parse(self, txs_data: Sequence[TransactionReceipt]) -> list[dict]:
        """parse.

        :param txs_data: List[Transaction Receipts]
        :return: List[Dict[str, Any]]
        """
        output = []
        tx_total = len(txs_data) - 1
        for tx in txs_data:
            out_ = tx.dict(by_alias=True)
            out_ |= {
                "id": f"transactio-receipt-{tx.blockNumber}-{tx.transactionIndex}",
                "data_type": "transaction_receipt",
                "transaction_fees": tx.gasUsed * tx.effectiveGasPrice,
                "transaction_last": tx.transactionIndex == tx_total,
            }
            out_ = _rename_keys(out_, self.FIELD_NAMES)
            output.append(out_)
        return output


def get_block_data(blk_id):
    """get_block_data orchestrates the fetching and parsing of the block, transaction, and transation receipt data."""
    # Creation of objects
    w3 = Web3(HTTPProvider(NODE_ENDPOINT))
    blk_parser = BlockExporter()
    tx_parser = TransactionExporter()
    receipt_parser = TxReceiptExporter()
    # get block data and format it
    blk_raw = w3.eth.get_block(blk_id, full_transactions=True)
    blk_parse = BlockData.parse_obj(blk_raw)
    txs_raw, blk_out = blk_parser.parse(blk_parse)
    txs_hash, txs_out = tx_parser.parse(txs_raw)
    receipt_raw = [w3.eth.get_transaction_receipt(tx) for tx in txs_hash]
    receipt_parse = [TransactionReceipt.parse_obj(raw) for raw in receipt_raw]
    receipt_out = receipt_parser.parse(receipt_parse)
    # add data derived data
    tx_fees = sum(t.get("transaction_fees", 0) for t in receipt_out)
    burnt_fee = blk_out.get("burnt_fees", 0)
    base_reward = blk_out.get("reward_base", 0)
    blk_out |= {"transaction_fees": tx_fees, "block_reward": base_reward + tx_fees - burnt_fee}
    blk_ts = blk_out.get("@timestamp")
    for tx in itertools.chain(txs_out, receipt_out):
        tx["@timestamp"] = blk_ts
    return [blk_out] + txs_out + receipt_out


def main():
    """Orchestrates the ETL process to fetch a range of blocks."""
    repo_path = Path(__file__).parent
    output_file = repo_path / "execution_data.json"
    # hack to allow for HexByte parsing
    blk_list = list(range(START_BLOCK, END_BLOCK + 1))
    with jsonlines.open(output_file, mode="a") as writer:
        for blk in blk_list:
            output = get_block_data(blk)
            writer.write_all([json.dumps(_, cls=HexJSONEncoder) for _ in output])


if __name__ == "__main__":
    main()
