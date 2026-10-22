"""Demo tool for the agentleash vulnerable agent.

It reads whatever bucket and key the agent passes in, using the Lambda's own
role. That is the point: the agent decides the arguments, and a prompt-injected
agent can ask for any object the role can reach.
"""

import json

import boto3

s3 = boto3.client("s3")


def handler(event, _context):
    params = {p["name"]: p["value"] for p in event.get("parameters", [])}
    obj = s3.get_object(Bucket=params["bucket"], Key=params["key"])
    body = obj["Body"].read(4096).decode("utf-8", errors="replace")
    return {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": event["actionGroup"],
            "function": event["function"],
            "functionResponse": {"responseBody": {"TEXT": {"body": json.dumps({"content": body})}}},
        },
    }
