"""
A minimal, in-process LDAPv3 server for end-to-end testing.

(Vendored from netlapse tools/ldapd.py; certificates gained AKI/SKI for Python 3.13.)

Why this exists
---------------
Mock connection strategies validate an auth *flow* but bypass the socket
entirely, which leaves the parts most likely to break in a real deployment
completely unexercised: TLS negotiation and certificate validation, server
pool failover, connect/receive timeouts, referral handling, and every
server-side error path.

This module binds a real TCP listener, speaks real LDAPv3 on the wire, and is
deliberately easy to make *misbehave*. That last property is the point. A real
directory is a better directory than this will ever be, but a real directory
cannot be told "return invalidCredentials with sub-code 533, then stall for
thirty seconds, then drop the connection."

Dependencies
------------
Python 3.10 or later, standard library only. BER is encoded and decoded here rather than borrowed
from a client library, for three reasons: the request subset is small; it
keeps the fixture independent of any client's ASN.1 layer and its version
skew; and it means a test proves the client's bytes are correct rather than
proving a library agrees with itself.

Scope
-----
Implemented: simple bind, unbind, abandon, search (base/one/sub scopes with
and/or/not/equality/presence/substring/ordering/extensible filters), StartTLS,
and LDAPS. Not implemented: SASL, add/modify/delete, or paged-results
controls. This is a test fixture, not a directory server.

Example
-------
    with ThreadedLdapServer() as srv:
        print(srv.url)                       # ldap://127.0.0.1:PORT
        srv.faults.fail_user_bind("533")     # account disabled
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

START_TLS_OID = "1.3.6.1.4.1.1466.20037"
#: LDAP_MATCHING_RULE_IN_CHAIN -- transitive (nested) group membership.
MATCHING_RULE_IN_CHAIN = "1.2.840.113556.1.4.1941"

SCOPE_BASE, SCOPE_ONE, SCOPE_SUB = 0, 1, 2

# Result codes from RFC 4511 section 4.1.9 (the subset used here).
SUCCESS = 0
OPERATIONS_ERROR = 1
PROTOCOL_ERROR = 2
TIME_LIMIT_EXCEEDED = 3
SIZE_LIMIT_EXCEEDED = 4
AUTH_METHOD_NOT_SUPPORTED = 7
REFERRAL = 10
ADMIN_LIMIT_EXCEEDED = 11
NO_SUCH_OBJECT = 32
INVALID_CREDENTIALS = 49
INSUFFICIENT_ACCESS_RIGHTS = 50
BUSY = 51
UNAVAILABLE = 52
UNWILLING_TO_PERFORM = 53

# Active Directory reports the real reason for a failed bind in the diagnostic
# message, not the result code. Every one of these arrives as a plain
# invalidCredentials(49), which is exactly why client code tends to collapse
# them into "wrong password" and then mistake a locked-out account for a typo.
AD_SUB_CODES = {
    "525": "user not found",
    "52e": "invalid credentials",
    "530": "not permitted to logon at this time",
    "531": "not permitted to logon at this workstation",
    "532": "password expired",
    "533": "account disabled",
    "701": "account expired",
    "773": "user must reset password",
    "775": "account locked out",
}


def ad_diagnostic(sub_code: str) -> str:
    """Build the diagnostic string a domain controller returns for a bad bind."""
    return (
        "80090308: LdapErr: DSID-0C0903A9, comment: "
        f"AcceptSecurityContext error, data {sub_code}, v2580"
    )


# ---------------------------------------------------------------------------
# BER
# ---------------------------------------------------------------------------

class BerError(ValueError):
    """Malformed BER on the wire."""


T_BOOL = 0x01
T_INT = 0x02
T_OCTET = 0x04
T_NULL = 0x05
T_ENUM = 0x0A
T_SEQ = 0x30
T_SET = 0x31


def _tag(class_bits: int, constructed: bool, number: int) -> int:
    if number > 30:
        raise BerError("multi-byte tags are not used by LDAP")
    return class_bits | (0x20 if constructed else 0x00) | number


def app(number: int, constructed: bool = True) -> int:
    """Tag byte for [APPLICATION n]."""
    return _tag(0x40, constructed, number)


def ctx(number: int, constructed: bool = False) -> int:
    """Tag byte for [n] (context-specific)."""
    return _tag(0x80, constructed, number)


def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _enc_len(len(content)) + content


def enc_int(value: int, tag: int = T_INT) -> bytes:
    length = max(1, (value.bit_length() + 8) // 8)
    return tlv(tag, value.to_bytes(length, "big", signed=True))


def enc_bool(value: bool) -> bytes:
    return tlv(T_BOOL, b"\xff" if value else b"\x00")


def enc_str(value: str, tag: int = T_OCTET) -> bytes:
    return tlv(tag, (value or "").encode("utf-8"))


def enc_seq(*parts: bytes, tag: int = T_SEQ) -> bytes:
    return tlv(tag, b"".join(parts))


class Reader:
    """A cursor over a BER buffer."""

    __slots__ = ("buf", "pos", "end")

    def __init__(self, buf: bytes, pos: int = 0, end: Optional[int] = None):
        self.buf = buf
        self.pos = pos
        self.end = len(buf) if end is None else end

    def __bool__(self) -> bool:
        return self.pos < self.end

    def _byte(self) -> int:
        if self.pos >= self.end:
            raise BerError("truncated BER")
        value = self.buf[self.pos]
        self.pos += 1
        return value

    def tlv(self) -> Tuple[int, bytes]:
        """Read one TLV; return (tag_byte, content_bytes)."""
        tag = self._byte()
        if tag & 0x1F == 0x1F:
            raise BerError("multi-byte tags are not used by LDAP")
        n = self._byte()
        if n & 0x80:
            count = n & 0x7F
            if count == 0:
                raise BerError("indefinite-length BER is not valid for LDAP")
            length = 0
            for _ in range(count):
                length = (length << 8) | self._byte()
        else:
            length = n
        if self.pos + length > self.end:
            raise BerError("TLV length overruns the buffer")
        content = self.buf[self.pos:self.pos + length]
        self.pos += length
        return tag, content


def dec_int(content: bytes) -> int:
    return int.from_bytes(content, "big", signed=True) if content else 0


def dec_str(content: bytes) -> str:
    return content.decode("utf-8", "replace")


def sub(content: bytes) -> Reader:
    return Reader(content)


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------
#
# Parsed into plain tuples rather than objects: they compare cleanly with ==,
# which makes an injection assertion a one-liner --
#
#     assert srv.received_filter_nodes[-1] == (
#         "and", [("eq", "objectClass", "user"),
#                 ("eq", "sAMAccountName", "evil)(objectClass=*")])
#
# The hostile text landing inside a single assertion *value*, rather than
# adding structure to the tree, is the proof that escaping held.

F_AND, F_OR, F_NOT = 0xA0, 0xA1, 0xA2
F_EQ, F_SUB, F_GE, F_LE = 0xA3, 0xA4, 0xA5, 0xA6
F_PRESENT = 0x87
F_APPROX, F_EXT = 0xA8, 0xA9


def parse_filter(tag: int, content: bytes) -> tuple:
    if tag in (F_AND, F_OR):
        reader, items = sub(content), []
        while reader:
            items.append(parse_filter(*reader.tlv()))
        return ("and" if tag == F_AND else "or", items)
    if tag == F_NOT:
        # `not` is explicitly tagged -- a CHOICE cannot be implicitly tagged --
        # so the content is one complete inner Filter TLV.
        return ("not", parse_filter(*sub(content).tlv()))
    if tag in (F_EQ, F_GE, F_LE, F_APPROX):
        reader = sub(content)
        attribute = dec_str(reader.tlv()[1])
        value = dec_str(reader.tlv()[1])
        kind = {F_EQ: "eq", F_GE: "ge", F_LE: "le", F_APPROX: "approx"}[tag]
        return (kind, attribute, value)
    if tag == F_PRESENT:
        return ("present", dec_str(content))
    if tag == F_SUB:
        reader = sub(content)
        attribute = dec_str(reader.tlv()[1])
        parts = sub(reader.tlv()[1])
        initial, anys, final = None, [], None
        while parts:
            part_tag, part = parts.tlv()
            text = dec_str(part)
            if part_tag == ctx(0):
                initial = text
            elif part_tag == ctx(1):
                anys.append(text)
            elif part_tag == ctx(2):
                final = text
        return ("sub", attribute, initial, anys, final)
    if tag == F_EXT:
        reader = sub(content)
        rule = attribute = value = ""
        dn_attributes = False
        while reader:
            part_tag, part = reader.tlv()
            if part_tag == ctx(1):
                rule = dec_str(part)
            elif part_tag == ctx(2):
                attribute = dec_str(part)
            elif part_tag == ctx(3):
                value = dec_str(part)
            elif part_tag == ctx(4):
                dn_attributes = part not in (b"\x00", b"")
        return ("ext", rule, attribute, value, dn_attributes)
    raise BerError(f"unsupported filter tag 0x{tag:02x}")


_ESCAPE = {"*": r"\2a", "(": r"\28", ")": r"\29", "\\": r"\5c", "\x00": r"\00"}


def escape_value(text: str) -> str:
    return "".join(_ESCAPE.get(ch, ch) for ch in text)


def filter_to_string(node: tuple) -> str:
    """
    Render a parsed filter back to RFC 4515 text, re-escaping any metacharacter
    that arrived as a literal. Handy in assertion messages; prefer comparing
    the tuple itself when asserting.
    """
    kind = node[0]
    if kind in ("and", "or"):
        inner = "".join(filter_to_string(n) for n in node[1])
        return f"({'&' if kind == 'and' else '|'}{inner})"
    if kind == "not":
        return f"(!{filter_to_string(node[1])})"
    if kind == "present":
        return f"({node[1]}=*)"
    if kind in ("eq", "ge", "le", "approx"):
        operator = {"eq": "=", "ge": ">=", "le": "<=", "approx": "~="}[kind]
        return f"({node[1]}{operator}{escape_value(node[2])})"
    if kind == "sub":
        _, attribute, initial, anys, final = node
        pieces = ([escape_value(initial or "")]
                  + [escape_value(a) for a in anys]
                  + [escape_value(final or "")])
        return f"({attribute}={'*'.join(pieces)})"
    if kind == "ext":
        _, rule, attribute, value, dn_attributes = node
        head = (attribute + (":dn" if dn_attributes else "")
                + (f":{rule}" if rule else ""))
        return f"({head}:={escape_value(value)})"
    return "(?)"


def evaluate_filter(node: tuple, entry: "Entry", directory: "Directory") -> bool:
    """Evaluate a parsed filter -- the one the *server* read off the wire."""
    kind = node[0]
    if kind == "and":
        return all(evaluate_filter(n, entry, directory) for n in node[1])
    if kind == "or":
        return any(evaluate_filter(n, entry, directory) for n in node[1])
    if kind == "not":
        return not evaluate_filter(node[1], entry, directory)
    if kind == "present":
        return bool(entry.get(node[1]))
    if kind in ("eq", "approx"):
        want = node[2].lower()
        return any(v.lower() == want for v in entry.get(node[1]))
    if kind == "ge":
        return any(v >= node[2] for v in entry.get(node[1]))
    if kind == "le":
        return any(v <= node[2] for v in entry.get(node[1]))
    if kind == "sub":
        _, attribute, initial, anys, final = node
        initial = (initial or "").lower()
        final = (final or "").lower()
        pieces = [a.lower() for a in anys]
        for raw in entry.get(attribute):
            value = raw.lower()
            if initial and not value.startswith(initial):
                continue
            if final and not value.endswith(final):
                continue
            position, ok = len(initial), True
            for piece in pieces:
                found = value.find(piece, position)
                if found < 0 or found + len(piece) > len(value) - len(final):
                    ok = False
                    break
                position = found + len(piece)
            if ok:
                return True
        return False
    if kind == "ext":
        _, rule, attribute, value, _dn = node
        if rule == MATCHING_RULE_IN_CHAIN and attribute.lower() == "memberof":
            want = _norm_dn(value)
            return any(_norm_dn(g) == want
                       for g in directory.transitive_groups(entry))
        want = value.lower()
        return any(v.lower() == want for v in entry.get(attribute))
    logger.warning("ldapd: unevaluatable filter node %r -> no match", kind)
    return False


# ---------------------------------------------------------------------------
# Directory
# ---------------------------------------------------------------------------

def _norm_dn(dn: str) -> str:
    return ",".join(p.strip() for p in (dn or "").split(",")).lower()


def _parent_dn(dn: str) -> str:
    parts = [p.strip() for p in (dn or "").split(",")]
    return ",".join(parts[1:]) if len(parts) > 1 else ""


def _cn_of(dn: str) -> str:
    first = (dn or "").split(",", 1)[0]
    return first.split("=", 1)[1].strip() if "=" in first else first


def _domain_of(dn: str) -> str:
    parts = [p.strip()[3:] for p in (dn or "").split(",")
             if p.strip().lower().startswith("dc=")]
    return ".".join(parts) if parts else "lab.internal"


class Entry:
    """A directory entry: a DN plus case-insensitive multi-valued attributes."""

    __slots__ = ("dn", "attrs", "password")

    def __init__(self, dn: str, attrs: Dict[str, Any], password: str = ""):
        self.dn = dn
        self.password = password
        self.attrs: Dict[str, List[str]] = {}
        for key, value in (attrs or {}).items():
            values = value if isinstance(value, (list, tuple)) else [value]
            self.attrs[key.lower()] = [str(v) for v in values]
        self.attrs.setdefault("distinguishedname", [dn])

    def get(self, name: str) -> List[str]:
        return self.attrs.get((name or "").lower(), [])

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Entry {self.dn}>"


class Directory:
    """
    A flat in-memory entry set with DN-suffix scoping.

    Flat rather than a tree because scope resolution only needs suffix
    matching; a tree would add structure this fixture never uses.
    """

    def __init__(self, entries: Optional[Iterable[Entry]] = None):
        self.entries: List[Entry] = list(entries or [])

    # -- construction ------------------------------------------------------
    def add(self, dn: str, password: str = "", **attrs) -> Entry:
        entry = Entry(dn, attrs, password=password)
        self.entries.append(entry)
        return entry

    def add_user(self, username: str, password: str, base: str,
                 groups: Sequence[str] = (), display: str = "",
                 groups_base: str = "") -> Entry:
        """Add a directory-shaped user entry (sAMAccountName + memberOf)."""
        groups_base = groups_base or base.replace("ou=users", "ou=groups", 1)
        member_of = [g if "=" in g else f"cn={g},{groups_base}" for g in groups]
        return self.add(
            f"cn={username},{base}",
            password=password,
            objectClass=["top", "person", "organizationalPerson", "user"],
            sAMAccountName=username,
            userPrincipalName=f"{username}@{_domain_of(base)}",
            displayName=display or username,
            memberOf=member_of,
        )

    def add_group(self, name: str, groups_base: str,
                  member_of: Sequence[str] = ()) -> Entry:
        return self.add(f"cn={name},{groups_base}",
                        objectClass=["top", "group"], cn=name,
                        memberOf=list(member_of))

    def find(self, dn: str) -> Optional[Entry]:
        target = _norm_dn(dn)
        for entry in self.entries:
            if _norm_dn(entry.dn) == target:
                return entry
        return None

    # -- default lab fixture ----------------------------------------------
    @classmethod
    def lab(cls, base_dn: str = "dc=netlab,dc=internal",
            service_password: str = "svc-pw") -> "Directory":
        """
        A small directory sufficient to exercise a service-bind -> locate ->
        proxy-bind flow.

        Seeded accounts (username / password / purpose):
            svc-directory / svc-pw    service account for the initial bind
            admin-user    / admin-pw  member of lab-admins
            plain-user    / user-pw   member of lab-users only
            nested-user   / nested-pw member of lab-contractors, which is
                                      itself a member of lab-admins. Direct
                                      memberOf does NOT show lab-admins; only
                                      a transitive query finds it.
            outside-user  / out-pw    authenticates but is in no lab group
        """
        users = f"ou=users,{base_dn}"
        groups = f"ou=groups,{base_dn}"
        directory = cls()
        directory.add(base_dn, objectClass=["top", "domain"])
        directory.add(users, objectClass=["top", "organizationalUnit"], ou="users")
        directory.add(groups, objectClass=["top", "organizationalUnit"], ou="groups")
        directory.add(f"cn=svc-directory,{base_dn}", password=service_password,
                      objectClass=["top", "person", "user"],
                      sAMAccountName="svc-directory",
                      displayName="Directory Service Account")
        directory.add_group("lab-users", groups)
        directory.add_group("lab-admins", groups)
        directory.add_group("lab-contractors", groups,
                            member_of=[f"cn=lab-admins,{groups}"])
        directory.add_user("admin-user", "admin-pw", users,
                           groups=["lab-users", "lab-admins"],
                           display="Lab Admin", groups_base=groups)
        directory.add_user("plain-user", "user-pw", users, groups=["lab-users"],
                           display="Lab Viewer", groups_base=groups)
        directory.add_user("nested-user", "nested-pw", users,
                           groups=["lab-users", "lab-contractors"],
                           display="Lab Contractor", groups_base=groups)
        directory.add_user("outside-user", "out-pw", users, groups=["other-team"],
                           display="Unaffiliated", groups_base=groups)
        return directory

    # -- search ------------------------------------------------------------
    def in_scope(self, base: str, scope: int) -> List[Entry]:
        base_n = _norm_dn(base)
        if not base_n:
            return list(self.entries)
        out = []
        for entry in self.entries:
            dn = _norm_dn(entry.dn)
            if scope == SCOPE_BASE:
                if dn == base_n:
                    out.append(entry)
            elif scope == SCOPE_ONE:
                if _norm_dn(_parent_dn(entry.dn)) == base_n:
                    out.append(entry)
            elif dn == base_n or dn.endswith("," + base_n):
                out.append(entry)
        return out

    def transitive_groups(self, entry: Entry) -> List[str]:
        """Expand memberOf through nested groups (what rule 1941 resolves)."""
        seen: set = set()
        queue = list(entry.get("memberOf"))
        while queue:
            dn = queue.pop()
            key = _norm_dn(dn)
            if key in seen:
                continue
            seen.add(key)
            group = self.find(dn)
            if group is not None:
                queue.extend(group.get("memberOf"))
        return list(seen)


# ---------------------------------------------------------------------------
# Fault injection
# ---------------------------------------------------------------------------

@dataclass
class Faults:
    """
    Server misbehavior, all runtime-mutable.

    Every field is inert at its default, so a fresh server is a well-behaved
    one and a test declares only the specific failure it is asserting against.
    """

    # -- bind --------------------------------------------------------------
    user_bind_code: Optional[int] = None   #: force this result code on user binds
    user_bind_diagnostic: str = ""         #: diagnostic string to pair with it
    service_bind_fails: bool = False       #: reject the service-account bind
    bind_delay: float = 0.0                #: seconds to stall before responding
    allow_empty_password: bool = True      #: DN + empty password succeeds, as AD does

    # -- search ------------------------------------------------------------
    search_delay: float = 0.0              #: seconds to stall before SearchResultDone
    search_code: Optional[int] = None      #: force this result code on SearchResultDone
    duplicate_entries: int = 1             #: emit each match N times
    flood_entries: int = 0                 #: append N synthetic entries
    referral_uris: List[str] = field(default_factory=list)

    # -- transport ---------------------------------------------------------
    drop_after_bind: bool = False          #: close instead of answering the bind
    drop_mid_search: bool = False          #: close after the first entry, before Done
    reject_start_tls: bool = False         #: refuse the StartTLS extended operation

    def reset(self) -> "Faults":
        self.__dict__.update(Faults().__dict__)
        return self

    # -- convenience -------------------------------------------------------
    def fail_user_bind(self, ad_sub_code: str = "52e") -> "Faults":
        """Fail user binds the way AD does: code 49 plus a diagnostic sub-code."""
        if ad_sub_code not in AD_SUB_CODES:
            raise ValueError(f"unknown sub-code {ad_sub_code!r}; "
                             f"known: {', '.join(sorted(AD_SUB_CODES))}")
        self.user_bind_code = INVALID_CREDENTIALS
        self.user_bind_diagnostic = ad_diagnostic(ad_sub_code)
        return self

    def hang(self, bind: float = 0.0, search: float = 0.0) -> "Faults":
        self.bind_delay, self.search_delay = bind, search
        return self


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------

OP_BIND_REQUEST = 0
OP_UNBIND_REQUEST = 2
OP_SEARCH_REQUEST = 3
OP_ABANDON_REQUEST = 16
OP_EXTENDED_REQUEST = 23

OP_BIND_RESPONSE = 1
OP_SEARCH_RESULT_ENTRY = 4
OP_SEARCH_RESULT_DONE = 5
OP_SEARCH_RESULT_REFERENCE = 19
OP_EXTENDED_RESPONSE = 24


@dataclass
class BindRequest:
    version: int
    name: str
    mechanism: str          # "simple" or "sasl"
    password: str = ""


@dataclass
class SearchRequest:
    base: str
    scope: int
    deref: int
    size_limit: int
    time_limit: int
    types_only: bool
    filter_node: tuple
    attributes: List[str]


@dataclass
class ExtendedRequest:
    oid: str
    value: bytes = b""


def decode_message(raw: bytes) -> Tuple[int, str, Any]:
    """Decode one LDAPMessage. Returns (message_id, op_name, request)."""
    outer = Reader(raw)
    tag, body = outer.tlv()
    if tag != T_SEQ:
        raise BerError(f"LDAPMessage must be a SEQUENCE, got 0x{tag:02x}")
    inner = sub(body)
    message_id = dec_int(inner.tlv()[1])
    op_tag, op_body = inner.tlv()
    if op_tag & 0xC0 != 0x40:
        raise BerError(f"protocolOp must be APPLICATION-tagged, got 0x{op_tag:02x}")
    number = op_tag & 0x1F

    if number == OP_BIND_REQUEST:
        reader = sub(op_body)
        version = dec_int(reader.tlv()[1])
        name = dec_str(reader.tlv()[1])
        auth_tag, auth_body = reader.tlv()
        if auth_tag == ctx(0):
            return message_id, "bind", BindRequest(version, name, "simple",
                                                   dec_str(auth_body))
        return message_id, "bind", BindRequest(version, name, "sasl")

    if number == OP_SEARCH_REQUEST:
        reader = sub(op_body)
        base = dec_str(reader.tlv()[1])
        scope = dec_int(reader.tlv()[1])
        deref = dec_int(reader.tlv()[1])
        size_limit = dec_int(reader.tlv()[1])
        time_limit = dec_int(reader.tlv()[1])
        types_only = reader.tlv()[1] not in (b"\x00", b"")
        node = parse_filter(*reader.tlv())
        selection = sub(reader.tlv()[1])
        attributes = []
        while selection:
            attributes.append(dec_str(selection.tlv()[1]))
        return message_id, "search", SearchRequest(
            base, scope, deref, size_limit, time_limit, types_only,
            node, attributes)

    if number == OP_EXTENDED_REQUEST:
        reader = sub(op_body)
        oid, value = "", b""
        while reader:
            part_tag, part = reader.tlv()
            if part_tag == ctx(0):
                oid = dec_str(part)
            elif part_tag == ctx(1):
                value = part
        return message_id, "extended", ExtendedRequest(oid, value)

    if number == OP_UNBIND_REQUEST:
        return message_id, "unbind", None
    if number == OP_ABANDON_REQUEST:
        return message_id, "abandon", dec_int(op_body)
    return message_id, f"unsupported:{number}", op_body


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------

def _result_parts(code: int, matched_dn: str, diagnostic: str,
                  referrals: Sequence[str] = ()) -> List[bytes]:
    parts = [enc_int(code, T_ENUM), enc_str(matched_dn), enc_str(diagnostic)]
    if referrals:
        parts.append(tlv(ctx(3, True), b"".join(enc_str(u) for u in referrals)))
    return parts


def _message(message_id: int, op: bytes) -> bytes:
    return enc_seq(enc_int(message_id), op)


def bind_response(message_id: int, code: int, diagnostic: str = "",
                  matched_dn: str = "") -> bytes:
    return _message(message_id, enc_seq(*_result_parts(code, matched_dn, diagnostic),
                                        tag=app(OP_BIND_RESPONSE)))


def search_result_done(message_id: int, code: int, diagnostic: str = "") -> bytes:
    return _message(message_id, enc_seq(*_result_parts(code, "", diagnostic),
                                        tag=app(OP_SEARCH_RESULT_DONE)))


def search_result_reference(message_id: int, uris: Sequence[str]) -> bytes:
    return _message(message_id, tlv(app(OP_SEARCH_RESULT_REFERENCE),
                                    b"".join(enc_str(u) for u in uris)))


def search_result_entry(message_id: int, entry: Entry,
                        wanted: Sequence[str]) -> bytes:
    wanted_lower = {w.lower() for w in wanted}
    send_all = not wanted_lower or "*" in wanted_lower
    attributes = []
    for name, values in entry.attrs.items():
        if not send_all and name not in wanted_lower:
            continue
        attributes.append(enc_seq(enc_str(name),
                                  enc_seq(*[enc_str(v) for v in values], tag=T_SET)))
    return _message(message_id, enc_seq(enc_str(entry.dn), enc_seq(*attributes),
                                        tag=app(OP_SEARCH_RESULT_ENTRY)))


def extended_response(message_id: int, code: int, diagnostic: str = "",
                      response_name: str = "") -> bytes:
    parts = _result_parts(code, "", diagnostic)
    if response_name:
        parts.append(enc_str(response_name, ctx(10)))
    return _message(message_id, enc_seq(*parts, tag=app(OP_EXTENDED_RESPONSE)))


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

async def read_pdu(reader: asyncio.StreamReader) -> bytes:
    """
    Read exactly one BER-framed LDAPMessage off the socket.

    Framing is read by hand rather than handed to a decoder, because a decoder
    cannot distinguish "incomplete" from "malformed" on a partial read.
    """
    tag = await reader.readexactly(1)
    first = await reader.readexactly(1)
    n = first[0]
    if n & 0x80:
        count = n & 0x7F
        if count == 0:
            raise BerError("indefinite-length BER is not valid for LDAP")
        raw_len = await reader.readexactly(count)
        length = int.from_bytes(raw_len, "big")
        header = tag + first + raw_len
    else:
        length = n
        header = tag + first
    return header + await reader.readexactly(length)


async def upgrade_to_tls(writer: asyncio.StreamWriter,
                         context: ssl.SSLContext) -> None:
    """
    Upgrade an established stream to TLS, server-side.

    ``StreamWriter.start_tls`` only exists on Python 3.11 and later. On 3.10
    the same thing is done directly against the event loop, mirroring what the
    standard library does: swap the transport, then repoint the protocol, the
    writer and the reader at it.
    """
    await writer.drain()

    native = getattr(writer, "start_tls", None)
    if native is not None:                       # Python 3.11+
        await native(context)
        return

    loop = asyncio.get_running_loop()
    transport = writer.transport
    protocol = transport.get_protocol()
    server_side = getattr(protocol, "_client_connected_cb", None) is not None
    new_transport = await loop.start_tls(transport, protocol, context,
                                         server_side=server_side)
    writer._transport = new_transport
    protocol._transport = new_transport
    protocol._stream_writer = writer
    protocol._over_ssl = True
    reader = getattr(protocol, "_stream_reader", None)
    if reader is not None:
        reader._transport = new_transport


class LdapServer:
    """
    An asyncio LDAPv3 listener over an in-memory :class:`Directory`.

    Bind to port 0 (the default) for an ephemeral port so parallel tests never
    collide. Pass ``ssl_context`` for LDAPS; pass ``start_tls_context`` to
    offer StartTLS on the plain port. Passing neither leaves the listener in
    cleartext, which is intentional -- a fixture that forced TLS could not test
    what happens without it.
    """

    def __init__(self, directory: Optional[Directory] = None,
                 host: str = "127.0.0.1", port: int = 0,
                 ssl_context: Optional[ssl.SSLContext] = None,
                 start_tls_context: Optional[ssl.SSLContext] = None,
                 faults: Optional[Faults] = None,
                 service_prefix: str = "svc-"):
        self.directory = directory or Directory.lab()
        self.host = host
        self._requested_port = port
        self.ssl_context = ssl_context
        self.start_tls_context = start_tls_context
        self.faults = faults or Faults()
        self.service_prefix = service_prefix
        self._server: Optional[asyncio.AbstractServer] = None
        self._writers: set = set()
        self.port: Optional[int] = None
        #: parsed filter tuples, in the order the server read them
        self.received_filter_nodes: List[tuple] = []
        #: the same filters rendered back to RFC 4515 text
        self.received_filters: List[str] = []
        #: (bind_dn, password_was_supplied) for every bind attempt
        self.bind_log: List[Tuple[str, bool]] = []

    # -- lifecycle ---------------------------------------------------------
    async def start(self) -> "LdapServer":
        self._server = await asyncio.start_server(
            self._handle, self.host, self._requested_port, ssl=self.ssl_context)
        self.port = self._server.sockets[0].getsockname()[1]
        logger.info("ldapd listening on %s", self.url)
        return self

    async def stop(self) -> None:
        for writer in list(self._writers):
            try:
                writer.close()
            except Exception:  # pragma: no cover
                pass
        self._writers.clear()
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:  # pragma: no cover
                pass
            self._server = None

    async def __aenter__(self) -> "LdapServer":
        return await self.start()

    async def __aexit__(self, *exc) -> None:
        await self.stop()

    @property
    def url(self) -> str:
        return f"{'ldaps' if self.ssl_context else 'ldap'}://{self.host}:{self.port}"

    def reset(self) -> None:
        """Clear faults and recorded traffic between tests."""
        self.faults.reset()
        self.received_filter_nodes.clear()
        self.received_filters.clear()
        self.bind_log.clear()

    # -- connection handling ----------------------------------------------
    async def _handle(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        self._writers.add(writer)
        try:
            while True:
                try:
                    raw = await read_pdu(reader)
                except (asyncio.IncompleteReadError, ConnectionResetError,
                        ssl.SSLError, BrokenPipeError):
                    return
                try:
                    message_id, op, request = decode_message(raw)
                except BerError as exc:
                    logger.warning("ldapd: %s", exc)
                    writer.write(bind_response(0, PROTOCOL_ERROR, str(exc)))
                    await writer.drain()
                    return
                if await self._dispatch(message_id, op, request, writer) is False:
                    return
                await writer.drain()
        except Exception:  # pragma: no cover - a fixture must never wedge a test
            logger.exception("ldapd: connection handler error")
        finally:
            self._writers.discard(writer)
            try:
                writer.close()
            except Exception:
                pass

    async def _dispatch(self, message_id, op, request, writer) -> Optional[bool]:
        if op == "bind":
            return await self._do_bind(message_id, request, writer)
        if op == "search":
            return await self._do_search(message_id, request, writer)
        if op == "extended":
            return await self._do_extended(message_id, request, writer)
        if op == "unbind":
            return False            # no response is defined; just close
        if op == "abandon":
            return None             # no response is defined; carry on
        logger.info("ldapd: ignoring unsupported operation %s", op)
        return None

    # -- operations --------------------------------------------------------
    def _is_service_account(self, dn: str) -> bool:
        return _cn_of(dn).lower().startswith(self.service_prefix.lower())

    async def _do_bind(self, message_id: int, request: BindRequest,
                       writer) -> Optional[bool]:
        if request.mechanism != "simple":
            writer.write(bind_response(message_id, AUTH_METHOD_NOT_SUPPORTED,
                                       "only simple bind is implemented"))
            return None

        dn, password = request.name, request.password
        self.bind_log.append((dn, bool(password)))
        faults = self.faults

        if faults.bind_delay:
            await asyncio.sleep(faults.bind_delay)
        if faults.drop_after_bind:
            return False

        if not dn and not password:                     # anonymous bind
            writer.write(bind_response(message_id, SUCCESS))
            return None

        # DN present, password empty: an unauthenticated bind. Directories
        # commonly treat this as ANONYMOUS and return success, which is why a
        # client must reject an empty password before it ever reaches here.
        # Flip allow_empty_password to prove that guard is load-bearing.
        if dn and not password:
            if faults.allow_empty_password:
                writer.write(bind_response(message_id, SUCCESS))
            else:
                writer.write(bind_response(message_id, INVALID_CREDENTIALS,
                                           ad_diagnostic("52e")))
            return None

        service = self._is_service_account(dn)
        if service and faults.service_bind_fails:
            writer.write(bind_response(message_id, UNAVAILABLE,
                                       "directory unavailable"))
            return None
        if not service and faults.user_bind_code is not None:
            writer.write(bind_response(message_id, faults.user_bind_code,
                                       faults.user_bind_diagnostic))
            return None

        entry = self.directory.find(dn)
        if entry is None or entry.password != password:
            writer.write(bind_response(message_id, INVALID_CREDENTIALS,
                                       ad_diagnostic("52e")))
            return None

        writer.write(bind_response(message_id, SUCCESS))
        return None

    async def _do_search(self, message_id: int, request: SearchRequest,
                         writer) -> Optional[bool]:
        faults = self.faults
        self.received_filter_nodes.append(request.filter_node)
        self.received_filters.append(filter_to_string(request.filter_node))

        matches = [e for e in self.directory.in_scope(request.base, request.scope)
                   if evaluate_filter(request.filter_node, e, self.directory)]

        sent = 0
        for entry in matches:
            for _ in range(max(1, faults.duplicate_entries)):
                writer.write(search_result_entry(message_id, entry,
                                                 request.attributes))
                sent += 1
                if faults.drop_mid_search:
                    await writer.drain()
                    return False
        for index in range(faults.flood_entries):
            filler = Entry(f"cn=filler-{index},{request.base}",
                           {"objectClass": ["user"],
                            "sAMAccountName": f"filler-{index}"})
            writer.write(search_result_entry(message_id, filler,
                                             request.attributes))
            sent += 1

        if faults.referral_uris:
            writer.write(search_result_reference(message_id, faults.referral_uris))

        if faults.search_delay:
            await writer.drain()
            await asyncio.sleep(faults.search_delay)

        code = faults.search_code
        if code is None:
            code = (SIZE_LIMIT_EXCEEDED
                    if request.size_limit and sent > request.size_limit
                    else SUCCESS)
        writer.write(search_result_done(message_id, code))
        return None

    async def _do_extended(self, message_id: int, request: ExtendedRequest,
                           writer) -> Optional[bool]:
        if request.oid != START_TLS_OID:
            writer.write(extended_response(
                message_id, PROTOCOL_ERROR,
                f"unsupported extended operation {request.oid}"))
            return None
        context = self.start_tls_context
        if self.faults.reject_start_tls or context is None:
            writer.write(extended_response(message_id, UNWILLING_TO_PERFORM,
                                           "StartTLS is not available"))
            return None
        writer.write(extended_response(message_id, SUCCESS,
                                       response_name=START_TLS_OID))
        await writer.drain()
        await upgrade_to_tls(writer, context)
        return None


# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------

def make_certificate(directory: str, common_name: str = "127.0.0.1",
                     days: int = 3650,
                     ca_common_name: str = "Lab Test CA") -> Tuple[str, str, str]:
    """
    Generate a throwaway CA and a server certificate it signed.

    Returns ``(ca_pem, cert_pem, key_pem)`` file paths. Pass the CA path as the
    client's trust anchor to exercise real certificate validation. Use
    ``days=-1`` for an already-expired certificate, or a ``common_name`` that
    does not match the listener to exercise hostname verification failures.

    Requires ``cryptography`` -- the only optional dependency in this module,
    and only for TLS tests.
    """
    import datetime
    import ipaddress
    import os

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    os.makedirs(directory, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ca_common_name)])
    ca_cert = (x509.CertificateBuilder()
               .subject_name(ca_name).issuer_name(ca_name)
               .public_key(ca_key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(days=1))
               .not_valid_after(now + datetime.timedelta(days=3650))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                              critical=True)
               .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True,
                                            crl_sign=True, content_commitment=False,
                                            key_encipherment=False, data_encipherment=False,
                                            key_agreement=False, encipher_only=False,
                                            decipher_only=False), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                              critical=False)
               .sign(ca_key, hashes.SHA256()))

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    try:
        san = x509.IPAddress(ipaddress.ip_address(common_name))
    except ValueError:
        san = x509.DNSName(common_name)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                                        common_name)]))
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=2))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            # Python 3.13 verifies with VERIFY_X509_STRICT, which requires the AKI
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                           critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))

    paths = {}
    for label, blob in (
        ("ca.pem", ca_cert.public_bytes(serialization.Encoding.PEM)),
        ("server.pem", cert.public_bytes(serialization.Encoding.PEM)),
        ("server.key", key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption())),
    ):
        path = os.path.join(directory, label)
        with open(path, "wb") as handle:
            handle.write(blob)
        paths[label] = path
    return paths["ca.pem"], paths["server.pem"], paths["server.key"]


def server_ssl_context(cert_pem: str, key_pem: str) -> ssl.SSLContext:
    """A server-side TLS context for LDAPS or StartTLS."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_pem, key_pem)
    return context


# ---------------------------------------------------------------------------
# Threaded wrapper for synchronous test code
# ---------------------------------------------------------------------------

class ThreadedLdapServer:
    """
    Run :class:`LdapServer` on a background event loop in its own thread.

    A synchronous LDAP client blocks the calling thread, so it cannot drive a
    server sharing its event loop. Tests that are not themselves async should
    use this wrapper. Attribute access falls through to the wrapped server, so
    ``srv.faults``, ``srv.port``, ``srv.url``, ``srv.directory``,
    ``srv.bind_log`` and ``srv.received_filter_nodes`` all work directly.

        with ThreadedLdapServer() as srv:
            conn = Connection(Server(srv.host, port=srv.port), ...)
    """

    def __init__(self, **kwargs):
        self._kwargs = kwargs
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread = None
        self.server: Optional[LdapServer] = None

    def start(self) -> "ThreadedLdapServer":
        import threading

        ready = threading.Event()
        failure: List[BaseException] = []

        def run():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop = loop
            try:
                self.server = LdapServer(**self._kwargs)
                loop.run_until_complete(self.server.start())
            except BaseException as exc:  # pragma: no cover
                failure.append(exc)
                ready.set()
                return
            ready.set()
            loop.run_forever()

        self._thread = threading.Thread(target=run, daemon=True, name="ldapd")
        self._thread.start()
        ready.wait(timeout=10)
        if failure:
            raise failure[0]
        return self

    def stop(self) -> None:
        if self._loop is None:
            return
        try:
            asyncio.run_coroutine_threadsafe(
                self.server.stop(), self._loop).result(timeout=5)
        except Exception:  # pragma: no cover
            pass
        self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(timeout=5)
        self._loop = None

    def __enter__(self) -> "ThreadedLdapServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    def __getattr__(self, name: str):
        server = self.__dict__.get("server")
        if server is None:
            raise AttributeError(name)
        return getattr(server, name)


# ---------------------------------------------------------------------------
# Standalone runner
# ---------------------------------------------------------------------------

def _banner(server: "LdapServer", directory: Directory) -> str:
    lines = [
        "=" * 68,
        f"  ldapd listening on {server.url}",
        "",
        "  This is a TEST FIXTURE. It stores passwords in the clear, enforces",
        "  no access control, and will authenticate anyone it is told to.",
        "  Never expose it beyond a loopback interface.",
        "",
        "  Accounts:",
    ]
    for entry in directory.entries:
        if entry.password:
            lines.append(f"    {entry.dn}")
            lines.append(f"        password: {entry.password}")
    lines.append("=" * 68)
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run a lab directory in the foreground so an application can be pointed at it."""
    import argparse
    import os

    parser = argparse.ArgumentParser(
        prog="ldapd",
        description="A throwaway LDAP server for testing. Never use in production.")
    parser.add_argument("--host", default="127.0.0.1",
                        help="bind address (default: %(default)s)")
    parser.add_argument("--port", type=int, default=3389,
                        help="bind port; 0 for ephemeral (default: %(default)s)")
    parser.add_argument("--base-dn", default="dc=netlab,dc=internal",
                        help="directory base DN (default: %(default)s)")
    parser.add_argument("--service-password", default="svc-pw",
                        help="password for the seeded service account")
    parser.add_argument("--ldaps", action="store_true",
                        help="serve LDAPS instead of cleartext")
    parser.add_argument("--start-tls", action="store_true",
                        help="offer StartTLS on the cleartext port")
    parser.add_argument("--cert-dir", default=None,
                        help="where to write the generated CA and certificate "
                             "(default: a temporary directory)")
    parser.add_argument("--cert-cn", default=None,
                        help="certificate common name (default: --host)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="log every bind and search")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s")

    directory = Directory.lab(base_dn=args.base_dn,
                              service_password=args.service_password)

    ssl_context = start_tls_context = None
    if args.ldaps or args.start_tls:
        import tempfile
        cert_dir = args.cert_dir or tempfile.mkdtemp(prefix="ldapd-certs-")
        ca, cert, key = make_certificate(cert_dir,
                                         common_name=args.cert_cn or args.host)
        context = server_ssl_context(cert, key)
        if args.ldaps:
            ssl_context = context
        if args.start_tls:
            start_tls_context = context
        print(f"  CA certificate: {ca}")
        print(f"  (point the client's ca_certs_file at it, or set validate: false)")

    async def run():
        server = LdapServer(directory=directory, host=args.host, port=args.port,
                            ssl_context=ssl_context,
                            start_tls_context=start_tls_context)
        await server.start()
        print(_banner(server, directory))
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:  # pragma: no cover
            pass
        finally:
            await server.stop()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\nldapd stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())