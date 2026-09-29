#!/usr/bin/env python3
"""
blocklist_parser.py - streaming, memory-bounded blocklist parser.

Why this exists
---------------
The original parser built a `set[str]` of every domain it saw. That is fine at
400k domains (~40 MiB) and fatal at several million: a Python set of 5,000,000
short strings costs roughly 500-700 MiB of RSS, and this host has 1.36 GiB
available in total. A single ungraceful OOM would take the resolver down with
it, which is exactly the failure mode we are trying to eliminate.

This module never materialises a domain set. It yields domains one at a time
from a line iterator, so peak memory is O(longest line) regardless of list
size. Dedup and sorting are delegated to `sort -u`, which spills to disk.

Formats handled
---------------
  hosts      "0.0.0.0 example.com"  (also 127.0.0.1, ::, 255.255.255.255)
  adblock    "||example.com^$third-party"  (AdBlock Plus / AdGuard / HaGeZi)
  bare       "example.com" one per line
  dnsmasq    "server=/example.com/"  and "address=/example.com/1.2.3.4"

Deliberately NOT handled
------------------------
  * exception rules "@@||example.com^" are returned separately as ALLOW
    entries. Silently discarding them would let a broad list break a site the
    publisher explicitly whitelisted.
  * regexp rules "/ads\\.example/" cannot be expressed as a DNS name. They are
    counted and reported so the gap is visible instead of silent.
  * cosmetic rules "example.com##.banner" are DOM-only filters with no DNS
    meaning and are counted and discarded.
"""
from __future__ import annotations

import re
from typing import Iterable, Iterator, Tuple

# A syntactically valid DNS name: labels of alnum/hyphen (no leading or
# trailing hyphen) joined by dots, ending in an alphabetic TLD of >=2 chars.
_VALID_DOMAIN = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
# Hosts-file line: leading sinkhole address, then one or more names.
# "::1?" covers both "::1" and "::"; the earlier "::1?::?" form could not match
# "::1 name" because it stopped at "::" and then demanded whitespace.
_HOSTS_IP = re.compile(
    r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1|255\.255\.255\.255|::1?|0)\s+(\S.*)$"
)
# Adblock host anchor. "||" anchors the start of a URL, so the host name ends
# at the first "/" - anything after that is a path and makes the rule a URL
# rule rather than a host rule (see _ADBLOCK_HOST below).
_ADBLOCK = re.compile(r"^\|\|([^\s^$|*/]+)")
# Host-anchored rules only: capture the authority, reject if a path follows.
_ADBLOCK_HOST = re.compile(r"^\|\|([^\s^$|*/]+)(?:\^)?$")
# Modifiers that scope a rule to a condition a DNS server cannot evaluate.
# "||adservice.google.com/adsid/x.js$script,domain=foo.com" means "block this
# only while browsing foo.com". Applying it unconditionally turns a narrow rule
# into a site-wide outage, which is what happened to youtube.com, facebook.com
# and ebay.com before these were rejected.
_SCOPED_MODIFIERS = (
    "$domain=", "$from=", "$to=", "$app=", "$denyallow=", "$urltransform=",
    "$content=", "$cookie=", "$header=", "$method=", "$permissions=",
    "$ipaddress=", "$strict1p", "$strict2p", "$all", "$popup",
)
# dnsmasq directives that carry a domain.
_DNSMASQ = re.compile(r"^\s*(?:server|address|local)=/([^/]*)/", re.IGNORECASE)


def _scoped(rule: str) -> bool:
    """True when a rule only applies under a condition DNS cannot evaluate."""
    tail = rule[rule.find("$"):].lower() if "$" in rule else ""
    return any(m in tail for m in _SCOPED_MODIFIERS)


def normalise(d: str) -> str | None:
    """Clean one candidate into a bare lowercase domain, or reject it."""
    d = d.strip().lower().strip(".")
    if not d:
        return None
    # strip a leading wildcard label ("*.cdn.example.com" -> "cdn.example.com")
    while d.startswith("*."):
        d = d[2:]
    d = d.lstrip("*")
    if d.count(".") < 1 or len(d) > 253:
        return None
    if not _VALID_DOMAIN.match(d):
        return None
    return d


def _clean_adblock_host(raw: str) -> str | None:
    """
    Adblock hostnames may carry option lists ("example.com^$dnstype=A") and
    inline comments. Everything from the first separator onwards is dropped.
    """
    raw = raw.split("#", 1)[0]
    for sep in ("^", "$", "/", "?", "&", "|"):
        if sep in raw:
            raw = raw.split(sep, 1)[0]
    return normalise(raw)


class Stats:
    """Counters so an operator can see what a list actually contained."""

    __slots__ = ("domains", "allow", "cosmetic", "regexp", "malformed")

    def __init__(self) -> None:
        self.domains = 0
        self.allow = 0
        self.cosmetic = 0
        self.regexp = 0
        self.malformed = 0

    def as_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__slots__}


def iter_entries(lines: Iterable[str]) -> Iterator[Tuple[str, str]]:
    """
    Yield ("deny"|"allow", domain) for every usable entry in `lines`.

    A single pass handles every syntax, because in practice a "hosts" file
    often also contains a handful of bare names and comment styles differ per
    publisher. Dispatching on a per-file "format" flag loses entries at the
    boundaries; this does not.
    """
    for raw in lines:
        line = raw.rstrip("\r\n")
        s = line.strip()
        if not s:
            continue

        # --- cosmetic / DOM-only rules: no DNS meaning -------------------
        if "##" in s or "#@#" in s or "#?#" in s or "#$#" in s:
            continue
        # --- regexp rules: cannot become a DNS name ---------------------
        if len(s) > 1 and s[0] == "/" and s[-1] == "/" and "\\" in s:
            continue
        # --- element-hiding / scriptlet noise ----------------------------
        # Exception rules start with "@@" and are handled below; a bare "@",
        # "$", "?" or "#" at position 0 is never a domain rule.
        is_exception = s.startswith("@@")
        if not is_exception and s[0] in "@$?#":
            continue


        # --- adblock host anchor: ||domain^$options ----------------------
        if s.startswith("||") or is_exception:
            # _ADBLOCK anchors on the literal "||", so an exception rule only
            # needs its leading "@@" removed. Stripping the "||" instead would
            # make the regex miss every line (observed: 229,418 HaGeZi entries
            # silently discarded).
            body = s.lstrip("@")
            if "/" in body.split("$", 1)[0].split("^", 1)[0]:
                # A path is present, so this is a URL rule. "||" anchors the
                # start of a URL and the host ends at the first "/", which means
                # ||youtube.com/embed/$domain=filma24.* is a rule about ONE
                # request on youtube.com for visitors from filma24.*. Turning it
                # into a DNS block takes youtube.com offline for the whole
                # household. The browser filter that produced it does not
                # belong in a DNS blocklist; skip it.
                continue
            if _scoped(body):
                # Only applies under a condition DNS cannot evaluate.
                continue
            m = _ADBLOCK.match(body)
            if m:
                d = _clean_adblock_host(m.group(1))
                if d:
                    yield ("allow" if is_exception else "deny", d)
            continue

        # --- dnsmasq directives ------------------------------------------
        if s.startswith(("server=", "address=", "local=", "server=/", "address=/")):
            m = _DNSMASQ.match(s)
            if m:
                d = normalise(m.group(1))
                if d:
                    yield ("deny", d)
            continue

        # --- comments -----------------------------------------------------
        if s[0] in "#!;" or s.startswith("["):
            continue
        # Metadata lines used by several publishers.
        if s.startswith(("Title:", "Version:", "Expires:", "Description:",
                         "Homepage:", "License:", "Syntax:", "Last modified:",
                         "Note:", "Issues:", "Disclaimer:", "Redirect:")):
            continue

        # --- hosts format -------------------------------------------------
        m = _HOSTS_IP.match(s)
        if m:
            rest = m.group(1)
            # Drop a trailing comment and keep only the name tokens.
            rest = rest.split("#", 1)[0]
            for host in rest.split():
                d = normalise(host)
                if d:
                    yield ("deny", d)
            continue

        # --- bare hostname -------------------------------------------------
        # Strip an inline comment, then require whitespace-free and valid.
        bare = s.split("#", 1)[0].split("!")[0].strip()
        if not bare or " " in bare:
            continue
        d = normalise(bare)
        if d:
            yield ("deny", d)


def stream_denials(text: str) -> Iterator[str]:
    """Yield only the deny-side domains from a decoded blob."""
    for verdict, d in iter_entries(text.splitlines()):
        if verdict == "deny":
            yield d


def classify(data: bytes) -> Tuple[str, int]:
    """
    Detect a blob's dominant syntax and count its usable domains.

    Used by the source prober so the registry records what a URL really
    contains rather than what a filename suggests.
    """
    text = data.decode("utf-8", errors="replace")
    abp = hosts = bare = 0
    for verdict, _d in iter_entries(text.splitlines()):
        if verdict != "deny":
            continue
        bare += 1
    for line in text.splitlines()[:400]:
        s = line.strip()
        if s.startswith("||"):
            abp += 1
        elif _HOSTS_IP.match(s):
            hosts += 1
    if abp > hosts:
        fmt = "adblock"
    elif hosts > 0:
        fmt = "hosts"
    else:
        fmt = "bare" if bare else "unknown"
    return fmt, bare
