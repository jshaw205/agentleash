from agentleash.iam.conditions import evaluate_conditions
from agentleash.iam.tristate import Tri


def test_no_condition_is_true():
    assert evaluate_conditions(None, {}).value is Tri.TRUE


def test_unknown_key_is_unknown_and_reported():
    r = evaluate_conditions({"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}, {})
    assert r.value is Tri.UNKNOWN
    assert r.unresolved_keys == {"aws:SourceIp"}


def test_known_keys_resolve():
    block = {"StringEquals": {"aws:SourceAccount": "111122223333"}}
    assert evaluate_conditions(block, {"aws:SourceAccount": ["111122223333"]}).value is Tri.TRUE
    assert evaluate_conditions(block, {"aws:sourceaccount": ["999999999999"]}).value is Tri.FALSE


def test_like_and_negation():
    block = {"ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/admin-*"}}
    assert (
        evaluate_conditions(block, {"aws:PrincipalArn": ["arn:aws:iam::1:role/app"]}).value
        is Tri.TRUE
    )
    assert (
        evaluate_conditions(block, {"aws:PrincipalArn": ["arn:aws:iam::1:role/admin-x"]}).value
        is Tri.FALSE
    )


def test_if_exists_and_null():
    block = {"StringEqualsIfExists": {"aws:ResourceTag/env": "prod"}}
    assert evaluate_conditions(block, {"aws:ResourceTag/env": None}).value is Tri.TRUE
    assert evaluate_conditions(block, {"aws:ResourceTag/env": ["dev"]}).value is Tri.FALSE
    null = {"Null": {"aws:ResourceTag/env": "true"}}
    assert evaluate_conditions(null, {"aws:ResourceTag/env": None}).value is Tri.TRUE
    assert evaluate_conditions(null, {"aws:ResourceTag/env": ["dev"]}).value is Tri.FALSE


def test_for_all_values():
    block = {"ForAllValues:StringEquals": {"aws:TagKeys": ["a", "b"]}}
    assert evaluate_conditions(block, {"aws:TagKeys": ["a"]}).value is Tri.TRUE
    assert evaluate_conditions(block, {"aws:TagKeys": ["a", "c"]}).value is Tri.FALSE


def test_one_false_condition_beats_an_unknown_one():
    block = {
        "StringEquals": {"aws:SourceAccount": "1"},
        "IpAddress": {"aws:SourceIp": "10.0.0.0/8"},
    }
    assert evaluate_conditions(block, {"aws:SourceAccount": ["2"]}).value is Tri.FALSE
