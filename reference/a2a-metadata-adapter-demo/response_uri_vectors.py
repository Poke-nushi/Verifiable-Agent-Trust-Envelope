"""Actual demo responses over synthetic request IDs for Python/TypeScript checks."""
import copy
import json
from unittest.mock import patch

import a2a_metadata_adapter_demo as demo

REQUEST_IDS = (
    "request-1", "request 1", "依頼001", "request#part", "request?part",
    "request/part", "request%2Fpart", "request%literal", "..", "request\\part",
    "request\npart", "request\x00part", "request-🐈",
)


def response_vector(request_id):
    task = json.loads(demo.TASK_MESSAGE.read_bytes())
    reference = task["metadata"][demo.EXTENSION_URI]["admission_request"]
    admission_path = demo.resolve_local_uri(reference["uri"])
    request = demo.binding.decode(demo.read_raw(admission_path))
    request["request_id"] = request_id
    raw = demo.binding.encode(request)
    reference["digest"]["value"] = demo.core.canonical_hash(request).removeprefix("sha-256:")
    read_raw, make_response = demo.read_raw, demo.make_task_response
    captured = {}

    def capture(task_message, metadata, decision):
        captured["admission_receipt"] = copy.deepcopy(decision["admission_receipt"])
        return make_response(task_message, metadata, decision)

    with patch.object(demo, "read_raw", side_effect=lambda path: raw if path == admission_path else read_raw(path)), \
            patch.object(demo, "make_task_response", side_effect=capture):
        response = demo.adapt_task_message(task)
    receipt = captured["admission_receipt"]
    return {"request_id": request_id, "admission_request": request, "admission_receipt": receipt,
            "post_execution_receipt": demo.build_post_execution_receipt(receipt), "response": response}


if __name__ == "__main__":
    print(json.dumps([response_vector(identifier) for identifier in REQUEST_IDS], ensure_ascii=True))
