"""eval.infra: one rule for "the machine failed", shared by eval.precheck and the orion-lm arm."""
import pytest
from neo4j.exceptions import AuthError, ServiceUnavailable, SessionExpired

from eval import infra


@pytest.mark.parametrize("text", [
    "ServiceUnavailable: Couldn't connect to localhost:7688",
    "SessionExpired: connection dropped",
    "AuthError: unauthorized",
    "RuntimeError: ServiceUnavailable: down",                 # orion/lm/slice re-raising GraphDB's error
    "GraphReadError: RuntimeError: SessionExpired: dropped",
    "RoutingServiceUnavailable: no routers",
])
def test_machine_failure_texts(text):
    assert infra.is_infra_text(text)


@pytest.mark.parametrize("text", [
    "CypherSyntaxError: Invalid input 'ServiceUnavailable: x'",   # quoting the word is not the failure
    "query timed out after 20 s: narrow it",
    "RuntimeError: [metal::malloc] Resource limit exceeded",
    "", None, 3,
])
def test_other_texts_are_not(text):
    assert not infra.is_infra_text(text)


def test_is_infra_walks_the_chain_and_reads_wrapped_texts():
    assert infra.is_infra(ServiceUnavailable("x")) and infra.is_infra(SessionExpired("x"))
    assert infra.is_infra(AuthError("x")) and infra.is_infra(infra.InfraError("joern missing"))
    assert infra.is_infra(RuntimeError("ServiceUnavailable: down"))
    try:
        try:
            raise SessionExpired("dropped")
        except SessionExpired as e:
            raise RuntimeError("persist failed") from e
    except RuntimeError as wrapped:
        assert infra.is_infra(wrapped)
    assert infra.is_infra(FileNotFoundError(2, "No such file", "/home/k/joern/joern-cli/joern-parse"))
    assert not infra.is_infra(FileNotFoundError(2, "No such file", "/tmp/x.json"))
    assert not infra.is_infra(RuntimeError("joern-parse failed (rc=1)"))
    assert not infra.is_infra(None)
