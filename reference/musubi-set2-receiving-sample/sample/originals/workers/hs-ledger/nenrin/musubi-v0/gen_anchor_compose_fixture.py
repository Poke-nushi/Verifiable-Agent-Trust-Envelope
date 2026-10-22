#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Writes anchor_compose_fixture.json: a detached .ots made by the OpenTimestamps reference library, so
anchor_compose's own reader is tested against another implementation's bytes, not against itself.

  python3 -m venv /tmp/ov && /tmp/ov/bin/pip install opentimestamps==0.4.5
  /tmp/ov/bin/python gen_anchor_compose_fixture.py

The tree has the shape a real stamp has after upgrade: a calendar nonce, a fork with a still pending
calendar on one side, aggregation, a transaction around the commitment and a block merkle path, then a
Bitcoin block header attestation. Nothing here is a real block; only the byte format is under test.
"""
import hashlib, io, json, os

import opentimestamps
from opentimestamps.core.op import OpAppend, OpPrepend, OpSHA256
from opentimestamps.core.notary import PendingAttestation, BitcoinBlockHeaderAttestation
from opentimestamps.core.timestamp import Timestamp, DetachedTimestampFile
from opentimestamps.core.serialize import StreamSerializationContext

HEIGHT = 968700
file_digest = hashlib.sha256(b"anchor_compose fixture batch bytes").digest()
root = Timestamp(file_digest)
t = root.ops.add(OpAppend(b"\x01calendar-nonce-16b"))
t = t.ops.add(OpSHA256())
t.attestations.add(PendingAttestation("https://alice.btc.calendar.opentimestamps.org"))
t2 = t.ops.add(OpPrepend(hashlib.sha256(b"aggregation sibling").digest()))
t2 = t2.ops.add(OpSHA256())
t2.attestations.add(PendingAttestation("https://bob.btc.calendar.opentimestamps.org"))
tx = t2.ops.add(OpPrepend(bytes.fromhex("0100000001" + "ab" * 36 + "00ffffffff01" + "00" * 8 + "22" + "6a20")))
tx = tx.ops.add(OpAppend(bytes.fromhex("00000000")))
tx = tx.ops.add(OpSHA256())
tx = tx.ops.add(OpSHA256())
for i, side in enumerate(("append", "prepend", "append")):
    sib = hashlib.sha256(b"merkle sibling %d" % i).digest()
    tx = tx.ops.add(OpAppend(sib) if side == "append" else OpPrepend(sib))
    tx = tx.ops.add(OpSHA256())
    tx = tx.ops.add(OpSHA256())
tx.attestations.add(BitcoinBlockHeaderAttestation(HEIGHT))

buf = io.BytesIO()
DetachedTimestampFile(OpSHA256(), root).serialize(StreamSerializationContext(buf))
data = buf.getvalue()

btc = [(m, a) for m, a in root.all_attestations() if isinstance(a, BitcoinBlockHeaderAttestation)]
pend = sorted(a.uri for m, a in root.all_attestations() if isinstance(a, PendingAttestation))


def names(ts, want):
    for op, child in ts.ops.items():
        if child is want:
            return [op.TAG_NAME]
        sub = names(child, want)
        if sub is not None:
            return [op.TAG_NAME] + sub
    return None


fx = {"library": opentimestamps.__version__ if hasattr(opentimestamps, "__version__") else "0.4.5",
      "ots_hex": data.hex(), "file_digest": file_digest.hex(), "height": HEIGHT,
      "msg_at_attestation": btc[0][0].hex(), "pending_uris": pend, "op_names": names(root, tx)}
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "anchor_compose_fixture.json")
with open(out, "w", encoding="utf-8") as f:
    json.dump(fx, f, indent=1, sort_keys=True)
    f.write("\n")
print("wrote", out, len(data), "bytes of .ots")
