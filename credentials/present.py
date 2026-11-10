#!/usr/bin/env python3
"""Builds the holder's side of an in-person presentation (ISO/IEC 18013-5) for every holder and
scenario: the session with the reader and the device signature.

  .venv/bin/python present.py

Each presentation is a fresh session with QR engagement (§8.2.1, §9.1.5.1):
  DeviceEngagement   {0: "1.0", 1: [1, #6.24(EDeviceKey)], 2: [[2, 1, BLE options]]}
  SessionTranscript  [#6.24(DeviceEngagement), #6.24(EReaderKey), null]   (null: QR handover)
with fresh ephemeral keys for the device and the reader. The device authenticates the session
with a signature (§9.1.3):
  DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, docType,
                          #6.24(DeviceNameSpaces = {})]
signed as a COSE_Sign1 with detached payload #6.24(DeviceAuthentication), ES256, by pycose (an
implementation independent of the circuits). In zero knowledge no element is disclosed in the
device response, so DeviceNameSpaces is empty.

Output: holders/<name>/<scenario>.cbor = {"SessionTranscript": bstr, "deviceSignature": COSE_Sign1}
"""

import os
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pycose.algorithms import Es256
from pycose.headers import Algorithm
from pycose.keys import EC2Key
from pycose.keys.curves import P256
from pycose.messages import Sign1Message

from holders import DOC_TYPE, HOLDERS, SCENARIOS

HERE = Path(__file__).resolve().parent


def cose_key_bytes(key):
    n = key.public_key().public_numbers()
    return cbor2.dumps({1: 2, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})


def session_transcript():
    e_device = ec.generate_private_key(ec.SECP256R1())
    e_reader = ec.generate_private_key(ec.SECP256R1())
    ble = {0: False, 1: True, 11: os.urandom(16)}  # mdoc peripheral server mode, its service UUID
    engagement = {0: "1.0", 1: [1, cbor2.CBORTag(24, cose_key_bytes(e_device))], 2: [[2, 1, ble]]}
    return [cbor2.CBORTag(24, cbor2.dumps(engagement)),
            cbor2.CBORTag(24, cose_key_bytes(e_reader)), None]


def device_signature(device_key, transcript):
    authentication = ["DeviceAuthentication", transcript, DOC_TYPE,
                      cbor2.CBORTag(24, cbor2.dumps({}))]
    payload = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(authentication)))
    d = device_key.private_numbers().private_value.to_bytes(32, "big")
    msg = Sign1Message(phdr={Algorithm: Es256}, payload=payload,
                       key=EC2Key(crv=P256, d=d, optional_params={}))
    sign1 = cbor2.loads(msg.encode(tag=False))
    sign1[2] = None  # detached: the reader rebuilds DeviceAuthenticationBytes from the session
    return sign1


def present(folder, scenario, device_key=None):
    """A fresh session for `scenario`, signed by the holder's device key (or `device_key`, a
    private key object), written to folder/<scenario>.cbor. Returns the SessionTranscript bytes."""
    if device_key is None:
        device_key = serialization.load_pem_private_key((folder / "device_key.pem").read_bytes(), None)
    transcript = session_transcript()
    (folder / f"{scenario}.cbor").write_bytes(cbor2.dumps({
        "SessionTranscript": cbor2.dumps(transcript),
        "deviceSignature": device_signature(device_key, transcript),
    }))
    return cbor2.dumps(transcript)


def main():
    for holder in HOLDERS:
        folder = HERE / "holders" / holder["name"]
        for scenario in SCENARIOS:
            tr = present(folder, scenario)
        print(f"{holder['name']}: {len(SCENARIOS)} sessions, SessionTranscript {len(tr)} bytes")


if __name__ == "__main__":
    main()
