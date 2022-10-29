"""This module parses the consenus layer Execution Payload."""
import datetime
import logging
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Type, Union

import pendulum
import pydantic
import requests
from jsonlines import jsonlines

Hex40 = pydantic.constr(regex="^0x[a-fA-F0-9]{40}$")
Hex64 = pydantic.constr(regex="^0x[a-fA-F0-9]{64}$")
HexExtraData = pydantic.constr(regex="^0x[a-fA-F0-9]{0,64}$")
HexTransaction = pydantic.constr(regex="^0x[a-fA-F0-9]{0,2147483648}$")
Hex96 = pydantic.constr(regex="^0x[a-fA-F0-9]{96}$")
Hex192 = pydantic.constr(regex="^0x[a-fA-F0-9]{192}$")
Hex512 = pydantic.constr(regex="^0x[a-fA-F0-9]{512}$")
ValIndex = pydantic.conint(ge=0)
PosInt = pydantic.conint(ge=0)

SLOTS_PER_EPOCH = 32
GENESIS_TIMESTAMP = 1_606_824_023
SECONDS_PER_SLOT = 12
ENDPOINT = "http://REPLACE_ME:3500"
START_SLOT, END_SLOT = 4_700_013, 4_892_031

logger = logging.getLogger("ExecutionPayload")


class EthereumVersion(Enum):
    """Available Ethereum Verions."""

    phase0 = "phase0"
    altair = "altair"
    bellatrix = "bellatrix"


class ExecutionPayload(pydantic.BaseModel):
    """The ExecutionPayload object from the CL Bellatrix spec."""

    parent_hash: Hex64
    fee_recipient: Hex40
    state_root: Hex64
    receipts_root: Hex64
    logs_bloom: Hex512
    prev_randao: Hex64
    block_number: PosInt
    gas_limit: PosInt
    gas_used: PosInt
    timestamp: PosInt
    extra_data: HexExtraData
    base_fee_per_gas: PosInt
    block_hash: Hex64
    transactions: pydantic.conlist(HexTransaction, max_items=1048576)


class BeaconBlockBody(pydantic.BaseModel):
    """The BeaconBlockBody object from the CL Bellatrix spec."""

    execution_payload: Optional[ExecutionPayload]


class BeaconBlock(pydantic.BaseModel):
    """The BeaconBlock object from the CL Bellatrix spec."""

    slot: PosInt
    proposer_index: ValIndex
    parent_root: Hex64
    state_root: Hex64
    body: BeaconBlockBody


class SignedBeaconBlock(pydantic.BaseModel):
    """The SignedBeaconBlock object envelope from the CL Bellatrix spec."""

    message: BeaconBlock
    signature: Hex192


class EthereumApiBlockResponse(pydantic.BaseModel):
    """The API response from /eth/v2/beacon/blocks/{block_id} method."""

    version: EthereumVersion
    execution_optimistic: bool
    data: SignedBeaconBlock


class EthereumApiValidatorStatus(Enum):
    """Possible Validator status as per <https://hackmd.io/ofFJ5gOmQpu1jjHilHbdQQ>."""

    pending_initialized = "pending_initialized"
    pending_queued = "pending_queued"
    active_ongoing = "active_ongoing"
    active_exiting = "active_exiting"
    active_slashed = "active_slashed"
    exited_unslashed = "exited_unslashed"
    exited_slashed = "exited_slashed"
    withdrawal_possible = "withdrawal_possible"
    withdrawal_done = "withdrawal_done"
    active = "active"
    pending = "pending"
    exited = "exited"
    withdrawal = "withdrawal"


class EthereumApiValidatorData(pydantic.BaseModel):
    """The Validator container from the CL phase0 spec."""

    pubkey: Hex96
    withdrawal_credentials: Hex64
    effective_balance: PosInt
    slashed: bool
    activation_eligibility_epoch: PosInt
    activation_epoch: PosInt
    exit_epoch: PosInt
    withdrawable_epoch: PosInt


class EthereumApiValidator(pydantic.BaseModel):
    """The Validators Balance information."""

    index: ValIndex
    balance: PosInt
    status: EthereumApiValidatorStatus
    validator: EthereumApiValidatorData


class EthereumApiValidators(pydantic.BaseModel):
    """The API response from /eth/v1/beacon/states/{state_id}/validators method."""

    execution_optimistic: bool
    data: Union[EthereumApiValidator, List[EthereumApiValidator]]


class ExecutionPayload:
    """ExecutionPayload.

    Parser class for the Execution Payload data.
    Adheres to the BlockParserInterface
    """

    def __init__(self, endpoint) -> None:
        """_init_.

        :param endpoint: url of the consensus layer endpoint
        """
        self.endpoint = endpoint

    def parse(self, api_response: EthereumApiBlockResponse, **kwarg) -> Dict[str, Dict[str, Any]]:
        """parse.

        :param api_response: parsed Block api responsed
        :return: dictionary with uuid as key and a dictionary with all the information of the execution payload

        Return example:
        {
            "execution-payload-123: {
                "parent_hash": "0x0",
                "fee_recipient": "0x0",
                "state_root": "0x0",
                "receipts_root": "0x0",
                "logs_bloom": "0x0",
                "block_number": 1,
                "gas_limit": 15,
                "gas_used": 3,
                "extra_data": "0x0",
                "base_fee_per_gas": 12,
                "block_hash": "0x0",
                "slot": 123,
                "proposer_index": 543,
                "@timestamp": "2022-01-30T13:49:32.304Z",
                "transaction_count": 300,
                "proposer_address": "0x0",
            }
        }
        """
        output: Dict[str, Dict[str, Any]] = {}
        message = api_response.data.message
        if not message:
            return output
        exec_payload = message.body.execution_payload
        if not exec_payload:
            return output
        output = exec_payload.dict(exclude={"transactions"})
        output |= {
            "slot": message.slot,
            "epoch": SlotToEpoch(message.slot),
            "proposer_index": message.proposer_index,
            "@timestamp": DateTimeConverter(SlotToTime(message.slot)),
            "data_type": "execution_payload",
            "transaction_count": len(exec_payload.transactions),
        }
        proposer_address = self._get_validator_address(val_id=message.proposer_index)
        output |= {"proposer_address": proposer_address[0] if proposer_address else None}
        return output

    def _get_validator_address(self, val_id=int) -> List[str]:
        try:
            val_data = get_validators(self.endpoint, validator_id=val_id).data
        except Exception:
            return []
        if not isinstance(val_data, list):
            return [val_data.validator.pubkey]
        return [val.validator.pubkey for val in val_data]


class EthereumAPIError(Exception):
    """Custom error for API messages."""

    def __init__(self, msg: str, code=None) -> None:
        """Add error code to exception."""
        super().__init__(msg)
        self.code = code


class RequestError(Exception):
    """Custom error to capture requests exceptions."""

    pass


class MissingHeightError(Exception):
    """Custom error to capture missing slots."""

    pass


def SlotToEpoch(slot: int) -> int:
    """Convert slot to epochs."""
    return slot // SLOTS_PER_EPOCH


def SlotToUnixEpoch(slot: int) -> int:
    """Convert slot into unix epoch."""
    return GENESIS_TIMESTAMP + slot * SECONDS_PER_SLOT


def SlotToTime(slot: int) -> datetime:
    """Convert slot into UTC localized datetime."""
    return datetime.datetime.fromtimestamp(SlotToUnixEpoch(slot), tz=datetime.timezone.utc)


def DateTimeConverter(dt_input: Union[datetime.datetime, datetime.date]) -> str:
    """Convert a datetime to a custom format."""
    if isinstance(dt_input, datetime.datetime):
        pendulum_ts = pendulum.instance(dt_input)
        return pendulum_ts.format(r"YYYY-MM-DDTHH:mm:ss.SSS\Z")
    if isinstance(dt_input, datetime.date):
        return dt_input.strftime("%Y-%m-%d")


def fetch(endpoint: pydantic.HttpUrl, **kwargs) -> dict:
    """Fetch data from ethereum's consensus API.

    :param endpoint:
    :type endpoint: str
    :param kwargs:
    :rtype: dict
    """
    try:
        api_response = requests.get(url=endpoint, headers=kwargs.get("headers"), params=kwargs.get("params"))
    except requests.RequestException as exc:
        logger.warning(exc)
        raise RequestError(exc)

    try:
        response_json = api_response.json()
    except requests.JSONDecodeError as exc:
        logger.warning(f"API did not return a valid JSON:\napi_endpoint={endpoint}, api_response={api_response}")
        raise RequestError(exc)

    return response_json


def parse_response(api_response: dict, parser: Type[pydantic.BaseModel], err_msg: str = "block can't be nil"):
    """parse_response.

    :param api_response:
    :type api_response: dict
    :param parser:
    :type parser: BaseModel
    :param err_msg:
    :type err_msg: str, defaults to 'block can't be nil'
    """
    if (response_code := api_response.get("code")) and (response_msg := api_response.get("message")):
        if err_msg in response_msg:
            logger.warning(f"Fetch returned empty result: message={response_msg}")
            raise MissingHeightError
        if response_code in [400, 404, 500]:
            raise EthereumAPIError(msg=response_msg, code=response_code)
        else:
            logger.warning(f"Unexpected error getting Attestations: api_response={api_response}")

    try:
        return parser.parse_obj(api_response)
    except pydantic.ValidationError as exc:
        logger.error(f"Pydantic failed to parse api response: api_response={api_response}, exception={exc}")
        raise


def get_block(endpoint: str, block_id: Union[int, str] = "head", **kwargs) -> EthereumApiBlockResponse:
    """get_block.

    :param endpoint:
    :type endpoint: str
    :param block_id:
    :type block_id: Union[int, str]
    :param kwargs:
    :rtype: EthereumApiBlockResponse
    """
    method: str = f"/eth/v2/beacon/blocks/{block_id}"
    api_response = fetch(endpoint + method, **kwargs)

    return parse_response(
        api_response=api_response, parser=EthereumApiBlockResponse, err_msg="Could not find requested block"
    )


def get_validators(
    endpoint: str,
    state_id: Union[int, str] = "head",
    validator_id: Optional[Union[int, str, list]] = None,
    status: Optional[str] = None,
    **kwargs,
) -> EthereumApiValidators:
    """Get and parse validators by state and id or public key along with status and balances.

    :param endpoint:
    :type endpoint: str
    :param state_id:
    :type state_id: Union[int, str], defaults to head
    :param validator_id:
    :type validator_id: Union[int, str, list, None], defaults to None
    :param status:
    :type status: Union[str, None], defaults to None
    :param kwargs:
    """
    method: str = f"/eth/v1/beacon/states/{state_id}/validators"
    params = {}
    if validator_id is not None:
        params |= {"id": validator_id}
    if status is not None:
        params |= {"status": status}

    api_response = fetch(endpoint=endpoint + method, params=params, **kwargs)

    return parse_response(
        api_response=api_response, parser=EthereumApiValidators, err_msg="Could not get validator container"
    )


def main():
    """Orchestrate the parsing of the execution payload from the beacon block response."""
    parser = ExecutionPayload(ENDPOINT)
    repo_path = Path(__file__).parent
    output_file = repo_path / "consesus_data.json"
    with jsonlines.open(output_file, mode="a") as f:
        for slot in range(START_SLOT, END_SLOT + 1):
            try:
                slot_data = get_block(ENDPOINT, slot)
            except Exception:
                continue
            f.write(parser.parse(slot_data))


if __name__ == "__main__":
    main()
