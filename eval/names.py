"""Joern method full name -> the bare function name a finding or a labeler uses.

ONE helper for every place a Joern `full_name` / `method_full_name` becomes a function name:
eval.pathgt (the proposed `fix_sites[].function`) and eval.match (L1's function match, the entry and
waypoint parts of the path levels). Formats, each read from a real Joern CPG (the decompressed
string pools of fixtures/NodeGoat/cpg.bin, fixtures/PyGoat/cpg.bin and a javasrc cpg.bin of
SasanLabs VulnerableApp; eval/tests/test_names.py holds the names verbatim):

  javasrc    <package>.<Class>.<method>:<return type>(<parameter types>)
             org.sasanlabs.Application.main:void(java.lang.String[])          -> main
             the ':signature' is dropped BEFORE splitting on '.' (its types contain dots);
             a constructor keeps Joern's name '<init>', a lambda its '<lambda>N'.
  jssrc      <file>::program[:<enclosing>...]:<name>
             app/data/user-dao.js::program:UserDAO:getUserById                 -> getUserById
             <file>::program alone is the file's top level                     -> None
             builtins use ':' too (__ecma.Date:getDay)                         -> getDay
  pythonsrc  <file>:<module>[.<Class>...].<name>
             challenge/views.py:<module>.DoItFast.delete                       -> delete
             <file>:<module> alone is module level                             -> None

None means "no function": module-level code has no name, so L1 falls back to the line window.
Anything else -- a name an agent wrote ("handler", "UserController.doPost", "Cls::m", "f()") --
keeps the earlier rule: drop a trailing "()", split on '.', '::' or ':', take the last segment.
"""
import re

_JS_PROGRAM = "::program"
_PY_MODULE = ":<module>"
# <dotted name>:<return type>(<params>) -- the return type has no parentheses, the name no ':'
_JAVA_SIG = re.compile(r"^([^:()\s]+):[^()]*\(.*\)$")
_SEP = re.compile(r"::|[.:]")


def function_name(full):
    """The function name inside a Joern full name (see the module doc), or None."""
    if full is None:
        return None
    s = str(full).strip()
    if not s:
        return None
    if _JS_PROGRAM in s:          # the file's top level when nothing follows "::program"
        rest = s.split(_JS_PROGRAM, 1)[1].strip(":")
        return rest.split(":")[-1] if rest else None
    if _PY_MODULE in s:           # module level when nothing follows ":<module>"
        rest = s.split(_PY_MODULE, 1)[1].strip(".")
        return rest.split(".")[-1] if rest else None
    m = _JAVA_SIG.match(s)
    if m:
        return m.group(1).split(".")[-1] or None
    if s.endswith("()"):
        s = s[:-2]
    parts = [p for p in _SEP.split(s) if p]
    return parts[-1] if parts else None
