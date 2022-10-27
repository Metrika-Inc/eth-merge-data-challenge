### Sources of information

We run a `geth/prysm` on mainnet and extracted all information by
querying the nodes. The method used were:

EL client:

* `eth_getBlockByHash`
* `eth_getTransactionReceipt`

CL client:

* `/eth/v2/beacon/blocks/{block_id}`
* `/eth/v1/beacon/states/{state_id}/validators/{validator_id}`

Relay nodes APIs were also queried via the method `/relay/v1/data/bidtraces/proposer_payload_delivered`

### Data

From the EL we extracted Block, Transaction and Transaction Receipts
for blocks between 15,345,393 to 15,729,394.
For the CL we got the execution payload
for the slots between 4,700,013 and 4,892,031.
Relay nodes were queried for the same slots as the CL.

We calculated:

* For each block of the EL:
  * `base_reward` based on
    [EIP-1234](https://eips.ethereum.org/EIPS/eip-1234) and
    [EIP-649](https://eips.ethereum.org/EIPS/eip-649)
    and zero after The Merge.
  * `transaction_count` as the length of the array containing the transaction
  * `burnt_fees` as `gasUsed * baseFeePerGas`
  * `transaction_fees` as the sum of `transaction_fee` in the
    transaction receipts
  * `block_reward` as `base_reward + transaction_fees - burnt_fees`
* For each transaction in the EL:
  * `transaction_last` as a `boolean` that identifies if the
    transaction is the last transaction in the block
* For each transaction receipt in the EL:
  * `transaction_fees` as `gasUsed * effectiveGasPrice`
  * `transaction_last` as a `boolean` that identifies if the
    transaction is the last transaction in the block
* For each block in the CL:
  * `proposer_address` by querying the validators method
  `/eth/v1/beacon/states/head/validators/{validator_id}` with
  `validator_id` equal to the `porposer_index`
  * `epoch` calculated from the `slot` and the `SLOTS_PER_EPOCH` from
  the specs
  * `transaction_count` as the length of the array of `transactions`

This information became the basis of our analysis. Each section describes
how the data was used and further transformed.
