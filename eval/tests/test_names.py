"""eval.names.function_name on REAL Joern full names.

Every name below was read verbatim (2026-10-22) from the decompressed string pool of a real Joern
CPG, not written by hand:
  jssrc     fixtures/NodeGoat/cpg.bin
  pythonsrc fixtures/PyGoat/cpg.bin
  javasrc   ~/Documents/sentryV2/VulnerableApp-master/cpg.bin (SasanLabs VulnerableApp)
"""
import pytest

from eval.names import function_name

JS = [
    ("app/routes/index.js::program:index", "index"),
    ("app/data/user-dao.js::program:UserDAO:getUserById", "getUserById"),
    ("app/data/allocations-dao.js::program:<lambda>0:<lambda>4:searchCriteria", "searchCriteria"),
    ("__ecma.Date:getDay", "getDay"),                          # a builtin callee: ':' separator too
    ("app/data/benefits-dao.js::program", None),               # the file's top level: no function
]
PYTHON = [
    ("dockerized_labs/sensitive_data_exposure/dataexposure/views.py:<module>.generate_api_key",
     "generate_api_key"),
    ("challenge/views.py:<module>.DoItFast.delete", "delete"),
    ("challenge/management/commands/populate_challenge.py:<module>.Command.handle", "handle"),
    ("challenge/__init__.py:<module>", None),                  # module level: no function
]
JAVA = [
    ("org.sasanlabs.Application.main:void(java.lang.String[])", "main"),
    ("org.sasanlabs.beans.ChallengeCardResponseBean$HintResponseBean.getOrder:int()", "getOrder"),
    ("org.sasanlabs.beans.AttackVectorResponseBean.<init>:void(java.util.List,java.lang.String,"
     "java.lang.String)", "<init>"),                           # constructor: Joern's own name, kept
    ("org.sasanlabs.service.vulnerability.idor.IDORVulnerability.<lambda>1:<unresolvedSignature>(2)",
     "<lambda>1"),
]


@pytest.mark.parametrize("full,want", JS + PYTHON + JAVA)
def test_real_joern_full_names(full, want):
    assert function_name(full) == want


def test_the_java_signature_is_dropped_before_splitting_on_dots():
    # the bug this helper fixes: splitting the whole name on '.' lands inside the parameter types
    full = "org.sasanlabs.beans.AttackVectorResponseBean.<init>:void(java.util.List,java.lang.String,java.lang.String)"
    assert full.replace(":", ".").split(".")[-1] == "String)"
    assert function_name(full) == "<init>"


@pytest.mark.parametrize("name,want", [
    ("handler", "handler"), ("handler()", "handler"), ("UserController.doPost", "doPost"),
    ("Cls::handler", "handler"), ("routes.index.handler", "handler"), (" sinkfn ", "sinkfn"),
    (None, None), ("", None),
])
def test_names_agents_write_keep_the_last_segment_rule(name, want):
    assert function_name(name) == want
