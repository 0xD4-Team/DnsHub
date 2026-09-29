#!/usr/bin/env python3
"""
blocklist_sources.py - the blocklist source registry.

Every entry here was verified by measurement from this host on 2026-09-29
(tools/probe_sources2.py). Entry counts are the pre-dedup domain totals that
the streaming parser actually extracted, not the publisher's advertised
numbers, and the format column is what detection found in the bytes.

Two structural decisions worth knowing about:

1. `superseded_by` - several publishers ship nested tiers. HaGeZi's light <
   normal < multi < pro < pro.plus < ultimate are strict supersets, so
   including the smaller ones adds zero domains while costing ~35 MiB of
   uplink and minutes of wall clock on a 48 ms WiFi link. 1Hosts Lite is a
   subset of Xtra for the same reason. Those entries are kept for auditability
   but excluded whenever their superseder is active.

2. `doh_blocklist` - HaGeZi's doh.txt blocks the public DoH endpoints. That
   looks odd on a resolver whose entire job is encrypted DNS, but it is the
   single most effective fix for the leak that made this project look broken:
   a browser with its own DoH enabled never asks the LAN resolver at all, so
   no blocklist can touch it. Blackholing the browser's DoH bootstrap makes
   it fall back to system DNS, which is dnshub. dnshub's own upstreams are
   addressed by IP literal, so this cannot break the resolver.
"""
from __future__ import annotations

# Categories are toggled independently by the dashboard.
CATEGORIES = {
    "core": "Baseline ad + malware filtering. Always safe, always included.",
    "ads": "Ad servers, pop-unders, URL shorteners, ad-driven app domains.",
    "privacy": "Trackers, fingerprinting, telemetry, dynamic-DNS and DoH "
               "endpoints that let software bypass this resolver.",
    "malware": "Malware, phishing, scam, fraud, abuse and crypto-scam feeds.",
    "social": "Social platform tracking. Optional; some logins use it.",
    "gambling": "Betting and casino infrastructure. Optional.",
    "adult": "Adult content. Optional.",
    "piracy": "Piracy and torrenting infrastructure. Optional.",
}

# Profiles map a friendly name to the set of categories it activates.
PROFILES = {
    "safe": ["core"],
    "daily": ["core", "ads", "privacy", "malware"],
    "strict": ["core", "ads", "privacy", "malware", "social", "gambling", "piracy"],
    "max": ["core", "ads", "privacy", "malware", "social", "gambling", "piracy", "adult"],
}
DEFAULT_PROFILE = "daily"

GH = "https://raw.githubusercontent.com/"
HAGEZI = GH + "hagezi/dns-blocklists/main/adblock/"

# name, url, categories, measured_entries, detected_format, superseded_by
SOURCES: list[dict] = [
    # ---------------- core ----------------
    dict(name="HaGeZi-Ultimate", url=HAGEZI + "ultimate.txt",
         cats=["core"], entries=285801, fmt="adblock"),
    dict(name="HaGeZi-ProPlus", url=HAGEZI + "pro.plus.txt",
         cats=["core"], entries=250610, fmt="adblock",
         superseded_by="HaGeZi-Ultimate"),
    dict(name="HaGeZi-Multi", url=HAGEZI + "multi.txt",
         cats=["core"], entries=200037, fmt="adblock",
         superseded_by="HaGeZi-Ultimate"),
    dict(name="OISD-Big", url="https://big.oisd.nl/",
         cats=["core"], entries=244439, fmt="adblock"),
    dict(name="AdGuard-SDNS", url="https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
         cats=["core"], entries=175546, fmt="adblock"),
    dict(name="StevenBlack", url=GH + "StevenBlack/hosts/master/hosts",
         cats=["core"], entries=74758, fmt="hosts"),

    # ---------------- ads ----------------
    dict(name="1Hosts-Xtra", url=GH + "badmojr/1Hosts/master/Xtra/hosts.txt",
         cats=["ads", "privacy"], entries=1115907, fmt="hosts"),
    dict(name="1Hosts-Lite", url=GH + "badmojr/1Hosts/master/Lite/hosts.txt",
         cats=["ads", "privacy"], entries=202867, fmt="hosts",
         superseded_by="1Hosts-Xtra"),
    dict(name="BlocklistProject-ads", url=GH + "BlocklistProject/Lists/main/ads.txt",
         cats=["ads"], entries=235842, fmt="hosts"),
    dict(name="HaGeZi-PopupAds", url=HAGEZI + "popupads.txt",
         cats=["ads"], entries=50703, fmt="adblock"),
    dict(name="HaGeZi-UrlShortener", url=HAGEZI + "urlshortener.txt",
         cats=["ads"], entries=9980, fmt="adblock"),
    dict(name="AdGuard-Base", url=GH + "AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
         cats=["ads"], entries=72503, fmt="adblock"),
    dict(name="AdGuard-Mobile", url=GH + "AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt",
         cats=["ads"], entries=1914, fmt="adblock"),
    dict(name="anudeep-adservers", url=GH + "anudeepND/blacklist/master/adservers.txt",
         cats=["ads"], entries=42516, fmt="hosts"),
    dict(name="MVPS", url="https://winhelp2002.mvps.org/hosts.txt",
         cats=["ads"], entries=8728, fmt="hosts"),
    dict(name="PeterLowe-yoyo", url="https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts",
         cats=["ads"], entries=3550, fmt="hosts"),
    dict(name="BLP-crypto", url=GH + "BlocklistProject/Lists/main/crypto.txt",
         cats=["ads"], entries=1274, fmt="hosts"),

    # ---------------- privacy ----------------
    dict(name="notracking", url=GH + "notracking/hosts-blocklists/master/domains.txt",
         cats=["privacy"], entries=550134, fmt="bare"),
    dict(name="BLP-tracking", url=GH + "BlocklistProject/Lists/main/tracking.txt",
         cats=["privacy"], entries=143866, fmt="hosts"),
    dict(name="HaGeZi-DoH", url=HAGEZI + "doh.txt",
         cats=["privacy"], entries=3334, fmt="adblock", doh_blocklist=True),
    dict(name="HaGeZi-DynDNS", url=HAGEZI + "dyndns.txt",
         cats=["privacy", "malware"], entries=1538, fmt="adblock"),
    dict(name="HaGeZi-NoSafeSearch", url=HAGEZI + "nosafesearch.txt",
         cats=["privacy"], entries=205, fmt="adblock"),
    dict(name="HaGeZi-Hoster", url=HAGEZI + "hoster.txt",
         cats=["privacy", "malware"], entries=1238, fmt="adblock"),
    dict(name="Firebog-EasyPrivacy", url="https://v.firebog.net/hosts/Easyprivacy.txt",
         cats=["privacy"], entries=43136, fmt="bare"),
    dict(name="Ultimate-Hosts-Blacklist",
         url=GH + "mitchellkrogza/Ultimate.Hosts.Blacklist/master/hosts/hosts0",
         cats=["privacy", "ads"], entries=153774, fmt="hosts"),
    dict(name="PiHole-SmartTV", url=GH + "Perflyst/PiHoleBlocklist/master/SmartTV.txt",
         cats=["privacy"], entries=497, fmt="bare"),
    dict(name="BLP-smart-tv", url=GH + "BlocklistProject/Lists/main/smart-tv.txt",
         cats=["privacy"], entries=77, fmt="hosts"),

    # ---------------- malware ----------------
    dict(name="BLP-abuse", url=GH + "BlocklistProject/Lists/main/abuse.txt",
         cats=["malware"], entries=434677, fmt="hosts"),
    dict(name="BLP-fraud", url=GH + "BlocklistProject/Lists/main/fraud.txt",
         cats=["malware"], entries=285023, fmt="hosts"),
    dict(name="BLP-phishing", url=GH + "BlocklistProject/Lists/main/phishing.txt",
         cats=["malware"], entries=190089, fmt="hosts"),
    dict(name="Phishing-Army-X", url="https://phishing.army/download/phishing_army_blocklist_extended.txt",
         cats=["malware"], entries=149516, fmt="bare"),
    dict(name="HaGeZi-Fake", url=HAGEZI + "fake.txt",
         cats=["malware"], entries=17383, fmt="adblock"),
    dict(name="AntiMalware-Hosts",
         url=GH + "DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt",
         cats=["malware"], entries=11766, fmt="hosts"),
    dict(name="BLP-scam", url=GH + "BlocklistProject/Lists/main/scam.txt",
         cats=["malware"], entries=8527, fmt="hosts"),
    dict(name="URLhaus", url="https://urlhaus.abuse.ch/downloads/hostfile/",
         cats=["malware"], entries=369, fmt="hosts"),

    # ---------------- social ----------------
    dict(name="HaGeZi-Social", url=HAGEZI + "social.txt",
         cats=["social"], entries=899, fmt="adblock"),

    # ---------------- gambling ----------------
    dict(name="HaGeZi-Gambling", url=HAGEZI + "gambling.txt",
         cats=["gambling"], entries=565053, fmt="adblock"),

    # ---------------- adult ----------------
    dict(name="HaGeZi-NSFW", url=HAGEZI + "nsfw.txt",
         cats=["adult"], entries=84504, fmt="adblock"),
    dict(name="AntiPorn-HOSTS", url=GH + "4skinSkywalker/Anti-Porn-HOSTS-File/master/HOSTS.txt",
         cats=["adult"], entries=70673, fmt="hosts"),
    dict(name="StevenBlack-FnGP",
         url=GH + "StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts",
         cats=["adult", "gambling"], entries=160074, fmt="hosts"),
    dict(name="StevenBlack-FakeNews",
         url=GH + "StevenBlack/hosts/master/extensions/fakenews/hosts",
         cats=["adult"], entries=2195, fmt="hosts"),

    # ---------------- piracy ----------------
    dict(name="HaGeZi-AntiPiracy", url=HAGEZI + "anti.piracy.txt",
         cats=["piracy"], entries=53044, fmt="adblock"),
]


def active_sources(profile: str, categories: list[str] | None = None) -> list[dict]:
    """
    Resolve a profile (or an explicit category list) to the sources to fetch.

    "core" is always included: without it there is no ad filtering at all, and
    a user who switched every optional category off almost certainly did not
    mean "stop blocking ads".
    """
    if categories is None:
        cats = set(PROFILES.get(profile, PROFILES[DEFAULT_PROFILE]))
    else:
        cats = set(categories)
    cats.add("core")

    chosen = [s for s in SOURCES if set(s["cats"]) & cats]
    names = {s["name"] for s in chosen}
    # Drop a source when a superseder that shares a category is also active.
    return [s for s in chosen
            if not (s.get("superseded_by") in names)]
