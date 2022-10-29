"""This module parses the relay API data."""
import json
import os
import time

import requests

INIT_SLOT = 4892031
END_SLOT = 4700013

relay_endpoints = [
    "https://boost-relay.flashbots.net",
    "https://bloxroute.max-profit.blxrbdn.com",
    "https://bloxroute.ethical.blxrbdn.com",
    "https://bloxroute.regulated.blxrbdn.com",
    "https://builder-relay-mainnet.blocknative.com",
    "https://mainnet-relay.securerpc.com",
    "https://relay.edennetwork.io",
]


def get_last_slot(data):
    """Get lowest slot in the API response."""
    return sorted([s["slot"] for s in data])[0]


def get_new_data(relay_endpoints, **kwargs):
    """Query new data from API endpoints and determines lowest slot returned."""
    api_method = "/relay/v1/data/bidtraces/proposer_payload_delivered"
    data = []
    slot = None
    for endpoint in relay_endpoints:
        api_request = requests.get(url=endpoint + api_method, **kwargs)
        json_request = api_request.json()
        data.append(json_request)
        if not slot:
            slot = get_last_slot(json_request)
        else:
            slot = min(slot, get_last_slot(json_request))
        time.sleep(1)
    return data, slot


def main():
    """Run queries until the END_SLOT is reached."""
    slot = INIT_SLOT
    while slot > END_SLOT:
        new_data, slot = get_new_data(relay_endpoints, params={"limit": 100})
    with os.open("relay_data.json", "wb") as file:
        json.dump(new_data, file)


if __name__ == "__main__":
    main()
