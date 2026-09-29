#!/usr/bin/env python3
"""
test_blocklist_parser.py - unit tests for the streaming parser.

A parser bug is silent and catastrophic here: a regex that fails to match
yields 0 domains, the blocklist still "compiles", the service still reports
healthy, and protection quietly drops to nothing. The HaGeZi case earlier in
this build was exactly that. These tests run before every registry change.
"""
import os
import sys

DEV = os.environ.get("DNSHUB_DEV") or os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
sys.path.insert(0, DEV)
from blocklist_parser import iter_entries, normalise, classify  # noqa: E402

PASS = 0
FAIL = 0


def check(name, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
    else:
        FAIL += 1
        print(f"  FAIL {name}\n       got  {got!r}\n       want {want!r}")


def one(line):
    return list(iter_entries([line]))


# --- the exact line that broke the first implementation ---------------------
check("hagezi real line", one("||asset-web.00701952218163.com^"),
      [("deny", "asset-web.00701952218163.com")])
check("hagezi sub path", one("||my.007moms.com^"),
      [("deny", "my.007moms.com")])

# --- adblock variants --------------------------------------------------------
check("abp options", one("||example.com^$third-party"),
      [("deny", "example.com")])
check("abp dnstype", one("||example.com^$dnstype=A|~NOTYPE"),
      [("deny", "example.com")])
check("abp exception", one("@@||example.com^"),
      [("allow", "example.com")])
# A scoped exception is dropped rather than promoted to a global allow. It says
# "on site X, allow example.com"; making it global would unblock example.com for
# everyone, which is how one publisher's exception undid nine sources' denials
# for doubleclick.net.
check("scoped exception dropped", one("@@||example.com^$domain=keep.me"), [])
check("abp dnstype exception kept", one("@@||ex.example^$dnstype=AAAA"),
      [("allow", "ex.example")])
check("abp path rule ignored", one("/banner/*"), [])
check("abp regexp ignored", one(r"/ads\.example\//"), [])

# --- hosts variants ----------------------------------------------------------
check("hosts 0.0.0.0", one("0.0.0.0 example.com"),
      [("deny", "example.com")])
check("hosts multi-name", one("0.0.0.0 a.example.com b.example.com"),
      [("deny", "a.example.com"), ("deny", "b.example.com")])
check("hosts comment", one("127.0.0.1 ads.example.com # tracker"),
      [("deny", "ads.example.com")])
check("hosts 255.255.255.255", one("255.255.255.255 evil.example.com"),
      [("deny", "evil.example.com")])
check("hosts ipv6", one("::1 evil.example.com"),
      [("deny", "evil.example.com")])

# --- dnsmasq -----------------------------------------------------------------
check("dnsmasq server", one("server=/example.com/"),
      [("deny", "example.com")])
check("dnsmasq address", one("address=/example.com/1.2.3.4"),
      [("deny", "example.com")])

# --- bare / wildcard ---------------------------------------------------------
check("bare domain", one("example.com"), [("deny", "example.com")])
check("bare uppercase", one("EXAMPLE.COM"), [("deny", "example.com")])
check("wildcard strip", one("*.cdn.example.com"),
      [("deny", "cdn.example.com")])

# --- URL path rules must NOT become domain blocks ----------------------------
# These are the real lines from AdGuard filter_2_Base that took youtube.com,
# facebook.com and ebay.com offline. "||" anchors the start of a URL, so a "/"
# means the rest is a path: the rule is about one request, not the host.
check("path rule embed", one("||youtube.com/embed/$domain=akhbarelyom.com"), [])
check("path rule stats",
      one("||youtube.com/api/stats/ads"), [])
check("path rule instream",
      one("||static.doubleclick.net/instream/ad_status.js$domain=youtube.com"), [])
check("path rule adservice",
      one("||adservice.google.com/adsid/integrator.js"
          "$script,redirect=noopjs,domain=961thebreeze.com"), [])
check("path rule wildcard",
      one("||youtube.com/embed/*?*&origin=*.filma24.*&widgetid"
          "$domain=filma24.*,important"), [])
check("scoped rule by app", one("||youtube.com^$app=com.apkpure.aegon"), [])
check("scoped rule by domain", one("||tracker.example^$domain=site.test"), [])
check("scoped rule from", one("||a.example^$from=evil.test"), [])
check("scoped rule to", one("||b.example^$to=good.test"), [])
check("scoped rule denyallow",
      one("||c.example^$denyallow=x.test,y.test"), [])

# ...while a plain host rule with harmless modifiers is still honoured.
check("host rule dnstype kept", one("||keep.example^$dnstype=A"), [("deny", "keep.example")])
check("host rule important kept", one("||keep2.example^$important"), [("deny", "keep2.example")])
check("host rule badfilter kept", one("||keep3.example^$badfilter"), [("deny", "keep3.example")])
check("pathless script rule kept",
      one("||d.example^$script,redirect=noopjs"), [("deny", "d.example")])

# exception rules keep the same treatment
check("exception host kept",
      one("@@||safe.example^$generichide"), [("allow", "safe.example")])
check("exception path dropped",
      one("@@||facebook.com/adsmanager/$generichide"), [])

# --- the exact apex rules the audit blamed ------------------------------------
for apex in ("youtube.com", "facebook.com", "ebay.com"):
    check(f"apex host rule would block {apex}", one(f"||{apex}^"),
          [("deny", apex)])

# --- things that must be dropped --------------------------------------------
check("cosmetic rule", one("example.com##.banner"), [])
check("cosmetic hash id", one("example.com#@#.ad"), [])
check("element hide", one("##.ad"), [])
check("comment hash", one("# a comment"), [])
check("comment bang", one("! Title: HaGeZi"), [])
check("header block", one("[Adblock Plus]"), [])
check("metadata", one("Expires: 8 hours"), [])
check("metadata title", one("! Title: something"), [])
check("blank", one("   "), [])
check("single label", one("localhost"), [])
check("leading hyphen", one("-bad.example.com"), [])
check("double dot", one("a..example.com"), [])
check("trailing dot kept clean", one("example.com."),
      [("deny", "example.com")])
check("no tld letters", one("1.2.3.4"), [])

# --- a realistic mixed HaGeZi header block ---------------------------------
hagezi_header = """[Adblock Plus]
! Title: HaGeZi's Multi PRO
! Expires: 8 hours
! Version: 2026.0928.0846.49
! Syntax: Adblock
!#include ./exception.txt
||cdn.007moms.com^
||my.007moms.com^
example.com##.ad
@@||safe.example.com^
"""
check("hagezi header block", list(iter_entries(hagezi_header.splitlines())),
      [("deny", "cdn.007moms.com"),
       ("deny", "my.007moms.com"),
       ("allow", "safe.example.com")])

# --- AdGuard Base: 161k real lines, must not produce a blocked apex ----------
import gzip as _gzip  # noqa: E402
import urllib.request as _req  # noqa: E402

_SAMPLE = """[Adblock Plus]
! Version: 2.4
! Title: AdGuard Base filter
||youtube.com/embed/*?*&origin=*.filma24.*&widgetid$domain=filma24.*,important
||youtube.com^$app=com.apkpure.aegon
||ads.youtube.com^
@@||static.doubleclick.net/instream/ad_status.js$domain=youtube.com
[$domain=facebook.com,path=/gaming]#$#body > .AdBox.Ad { display: block; }
~m.facebook.com,facebook.com#?#div[data-status-bar-color]
youtube.com#@##player-ads
ebay.de,ebay.com###itemDiv > div > a[href^="https://pulsar.ebay."]
||adservice.google.com/adsid/integrator.js$script,redirect=noopjs,domain=x.com
||doubleclick.net^
||adservice.google.com^
"""
got = [d for v, d in iter_entries(_SAMPLE.splitlines()) if v == "deny"]
check("adguard sample yields only the two real hosts", sorted(got),
      ["ads.youtube.com", "adservice.google.com", "doubleclick.net"])

# --- normalise() edge cases --------------------------------------------------
check("normalise idn ascii", normalise("xn--bcher-kva.example"),
      "xn--bcher-kva.example")
check("normalise too long", normalise("a" * 250 + ".example"), None)
check("normalise empty", normalise(""), None)
check("normalise just dot", normalise("."), None)

# --- classify() must agree with the streaming count ------------------------
sample = """[Adblock Plus]
! Title: t
||a.example^
||b.example^
||c.example^
"""
fmt, n = classify(sample.encode())
check("classify adblock fmt", fmt, "adblock")
check("classify adblock count", n, 3)

hosts_sample = """# Title: h
0.0.0.0 a.example
0.0.0.0 b.example
"""
fmt, n = classify(hosts_sample.encode())
check("classify hosts fmt", fmt, "hosts")
check("classify hosts count", n, 2)

# --- memory boundedness: a 400k-line input must not build a list -----------
import io  # noqa: E402
big = io.StringIO()
for i in range(400_000):
    big.write(f"||host{i}.example{i % 977}.com^\n")
seen = 0
for _v, _d in iter_entries(big.getvalue().splitlines()):
    seen += 1
check("streams 400k entries", seen, 400_000)

print(f"\n  {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
