"""Traffic types: what kind of traffic a conversation is (streaming, BitTorrent, gaming...).

Decided, most specific first, from:
  1. the remote's name -- the router's DNS cache maps addresses back to what your devices looked
     up (rr3---sn-xyz.googlevideo.com, ipv4-c001.nflxvideo.net ...), matched against known suffixes;
  2. well-known ports (6881-6999 BitTorrent, 3074 Xbox Live, 8801 Zoom, 993 IMAPS ...);
  3. a pattern: a LAN host talking to many unnamed peers on high ports is running P2P (BitTorrent
     picks random ports, so ports alone miss most of it);
  4. anything else on 80/443 is web, the rest "other".
It's an informed guess, not deep packet inspection: a CDN serving several services shows as the
one its name says, and encrypted traffic on 443 without a recognised name is "web".
Each category keeps a fixed hue so it means the same thing in every theme.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

CATEGORIES: List[Dict[str, Any]] = [
    {"id": "streaming", "label": "Video & music streaming", "hue": 330, "c": 0.16},
    {"id": "p2p", "label": "BitTorrent / P2P", "hue": 45, "c": 0.17},
    {"id": "gaming", "label": "Gaming", "hue": 140, "c": 0.16},
    {"id": "calls", "label": "Voice & video calls", "hue": 190, "c": 0.13},
    {"id": "social", "label": "Social & messaging", "hue": 10, "c": 0.12},
    {"id": "cloud", "label": "Cloud storage & backup", "hue": 285, "c": 0.15},
    {"id": "updates", "label": "Software updates", "hue": 100, "c": 0.15},
    {"id": "iot", "label": "Smart home / IoT", "hue": 75, "c": 0.14},
    {"id": "remote", "label": "VPN & remote access", "hue": 215, "c": 0.08},
    {"id": "mail", "label": "Email", "hue": 165, "c": 0.09},
    {"id": "web", "label": "Web", "hue": 245, "c": 0.13},
    {"id": "infra", "label": "DNS, time & network", "hue": 250, "c": 0.025},
    {"id": "other", "label": "Other", "hue": 0, "c": 0.0},
]
LABEL = {c["id"]: c["label"] for c in CATEGORIES}

# name suffixes / fragments -> category (matched against the lower-cased DNS name)
DOMAINS: List[Tuple[str, Tuple[str, ...]]] = [
    ("streaming", ("netflix.com", "nflxvideo.net", "nflxso.net", "nflximg.net", "nflxext.com", "googlevideo.com",
                   "youtube.com", "ytimg.com", "youtu.be", "youtube-nocookie.com", "twitch.tv", "ttvnw.net",
                   "jtvnw.net", "hulu.com", "hulustream.com", "huluim.com", "disneyplus.com", "dssott.com",
                   "bamgrid.com", "disney-plus.net", "primevideo.com", "aiv-cdn.net", "aiv-delivery.net",
                   "amazonvideo.com", "hbomax.com", "max.com", "hbo.com", "peacocktv.com",
                   "paramountplus.com", "cbsivideo.com", "plex.tv", "plex.direct", "spotify.com", "scdn.co",
                   "spotifycdn.com", "pandora.com", "tidal.com", "deezer.com", "vimeo.com", "vimeocdn.com",
                   "dailymotion.com", "crunchyroll.com", "roku.com", "sling.com", "fubo.tv", "pluto.tv", "tubi.tv",
                   "soundcloud.com", "sndcdn.com", "mzstatic.com", "itunes.apple.com", "tv.apple.com",
                   "music.apple.com", "aod.itunes.apple.com", "hls.itunes.apple.com")),
    ("calls", ("zoom.us", "zoom.com", "zoomgov.com", "teams.microsoft.com", "teams.live.com", "skype.com",
               "webex.com", "meet.google.com", "hangouts.google.com", "discord.media", "gotomeeting.com",
               "ringcentral.com", "bluejeans.com", "facetime.apple.com", "whereby.com", "jitsi")),
    ("gaming", ("steampowered.com", "steamcontent.com", "steamserver.net", "steamstatic.com", "steamcommunity.com",
                "valvesoftware.com", "xboxlive.com", "xbox.com", "playstation.net", "playstation.com",
                "sonyentertainmentnetwork.com", "epicgames.com", "epicgames.dev", "unrealengine.com",
                "riotgames.com", "leagueoflegends.com", "battle.net", "blizzard.com", "ea.com", "origin.com",
                "nintendo.net", "nintendo.com", "roblox.com", "rbxcdn.com", "minecraft.net", "mojang.com",
                "ubisoft.com", "ubi.com", "gog.com", "activision.com", "callofduty.com", "gamepass")),
    ("social", ("facebook.com", "fbcdn.net", "fb.com", "fbsbx.com", "instagram.com", "cdninstagram.com",
                "whatsapp.net", "whatsapp.com", "tiktok.com", "tiktokcdn.com", "tiktokv.com", "byteoversea.com",
                "ibytedtos.com", "twitter.com", "twimg.com", "x.com", "snapchat.com", "sc-cdn.net", "snapkit",
                "reddit.com", "redd.it", "redditmedia.com", "redditstatic.com", "linkedin.com", "licdn.com",
                "pinterest.com", "pinimg.com", "discord.com", "discordapp.com", "discordapp.net", "telegram.org",
                "t.me", "signal.org", "messenger.com", "threads.net", "tumblr.com", "bsky.app", "slack.com",
                "slack-edge.com", "irc.", "chat.google.com", "messages.google.com")),
    ("cloud", ("icloud.com", "icloud-content.com", "apple-cloudkit.com", "dropbox.com", "dropboxusercontent.com",
               "onedrive.live.com", "1drv.com", "onedrive.com", "drive.google.com", "backblaze.com",
               "backblazeb2.com", "s3.amazonaws.com", "s3-", ".s3.", "blob.core.windows.net", "box.com",
               "boxcloud.com", "mega.nz", "mega.co.nz", "pcloud.com", "wasabisys.com", "quickconnect.to",
               "tresorit.com", "sync.com", "idrive.com", "carbonite.com", "crashplan")),
    ("updates", ("windowsupdate.com", "update.microsoft.com", "delivery.mp.microsoft.com", "swcdn.apple.com",
                 "swdist.apple.com", "mesu.apple.com", "updates.cdn-apple.com", "appldnld.apple.com",
                 "download.mozilla.org", "ubuntu.com", "debian.org", "fedoraproject.org", "centos.org",
                 "rockylinux.org", "archlinux.org", "raspberrypi.org", "raspberrypi.com", "snapcraft.io",
                 "flathub.org", "dl.google.com", "gvt1.com", "update.googleapis.com", "download.nvidia.com",
                 "download.mikrotik.com", "upgrade.mikrotik.com", "pythonhosted.org", "docker.io",
                 "docker.com")),
    ("iot", ("tuya", "wyze", "ring.com", "nest.com", "smartthings.com", "ecobee.com", "meross", "tplinkcloud.com",
             "tplinknbu.com", "ezvizlife.com", "hik-connect.com", "arlo.com", "blinkforhome", "immedia-semi.com",
             "philips-hue.com", "meethue.com", "alexa.amazon.com", "avs-alexa", "sonos.com", "roborock",
             "ewelink", "home-assistant.io", "nabu.casa", "myq-cloud.com", "eufylife.com", "teslafleet",
             "teslamotors.com", "tesla.services")),
    ("remote", ("tailscale.com", "tailscale.io", "zerotier.com", "nordvpn.com", "expressvpn", "protonvpn",
                "mullvad.net", "teamviewer.com", "anydesk.com", "logmein.com", "parsec.app", "rustdesk.com")),
]

TCP, UDP = "TCP", "UDP"
# (category, protocol or None for any, ports)
PORTS: List[Tuple[str, Optional[str], Iterable[int]]] = [
    ("p2p", None, list(range(6881, 7000)) + [51413, 6969, 4662, 4672, 1337]),
    ("infra", None, [53, 853, 5353, 123, 67, 68, 161, 162, 1900, 5355]),
    ("mail", TCP, [25, 465, 587, 110, 995, 143, 993]),
    ("remote", None, [22, 3389, 5900, 5901, 5902, 5938, 1194, 51820, 500, 4500, 1701, 1723, 8291, 8728, 8729,
                      41641]),
    ("calls", UDP, list(range(3478, 3482)) + list(range(19302, 19310)) + list(range(8801, 8811)) + [5060, 5061]),
    ("calls", TCP, [5060, 5061, 8801, 8802]),
    ("gaming", None, [3074, 3075, 3659, 25565, 27015, 27016, 27017, 27036, 9308, 5222]),
    ("gaming", UDP, list(range(27000, 27101))),
    ("iot", None, [1883, 8883, 5683]),
    ("social", TCP, [6667, 6697, 5223]),
    ("web", None, [80, 443, 8080, 8443]),
]
_PORT_MAP: Dict[Tuple[Optional[str], int], str] = {}
for _cat, _proto, _ports in PORTS:
    for _p in _ports:
        _PORT_MAP.setdefault((_proto, _p), _cat)


def _matches(name: str, frag: str) -> bool:
    """'netflix.com' = that domain or any subdomain; 'irc.' = a host label 'irc'; '.s3.' / 's3-' /
    a word without dots ('tuya', 'wyze') = anywhere in the name."""
    if frag.endswith(".") and not frag.startswith("."):
        return name.startswith(frag) or ("." + frag) in name
    if frag.startswith(".") or frag.endswith("-") or "." not in frag:
        return frag in name
    return name == frag or name.endswith("." + frag)


def by_name(name: str) -> Optional[str]:
    n = (name or "").lower().rstrip(".")
    if not n:
        return None
    for cat, frags in DOMAINS:
        if any(_matches(n, f) for f in frags):
            return cat
    return None


def by_port(proto: str, port: int) -> Optional[str]:
    return _PORT_MAP.get((proto, port)) or _PORT_MAP.get((None, port))


def classify(proto: str, port: int, name: str = "") -> Tuple[str, str]:
    """-> (category id, why). `port` is the service (responder) port of the conversation."""
    proto = (proto or "").upper()
    cat = by_name(name)
    if cat:
        return cat, "name {}".format(name)
    if proto in ("GRE", "ESP", "AH"):
        return "remote", "{} tunnel".format(proto)
    if proto in ("ICMP", "ICMPV6"):
        return "infra", "ICMP"
    cat = by_port(proto, port)
    if cat:
        return cat, "{} port {}".format(proto.lower(), port)
    return "other", ""


def apply(pairs: Iterable[Dict[str, Any]], name_of) -> None:
    """Label each pair in place with cat / cat_why, including the P2P pattern across a host's pairs."""
    pairs = list(pairs)
    unnamed_high: Dict[str, set] = {}
    for p in pairs:
        if p.get("dir") == "lan":
            p["cat"], p["cat_why"] = "other", "LAN"
            continue
        name = name_of(p["remote"])
        p["cat"], p["cat_why"] = classify(p["proto"], int(p.get("port") or 0), name)
        if p["cat"] == "other" and not name and p["proto"] in (TCP, UDP) and int(p.get("port") or 0) >= 1024:
            unnamed_high.setdefault(p["local"], set()).add(p["remote"])
    # BitTorrent and friends talk to many peers on random high ports, none of which were looked up in DNS
    p2p_hosts = {h for h, peers in unnamed_high.items() if len(peers) >= 6}
    for p in pairs:
        if p["cat"] == "other" and p["local"] in p2p_hosts and int(p.get("port") or 0) >= 1024:
            p["cat"], p["cat_why"] = "p2p", "P2P pattern: {} unnamed high-port peers".format(len(unnamed_high[p["local"]]))


def rollup(items: Iterable[Tuple[str, float]]) -> Tuple[Dict[str, float], str]:
    """[(cat, bps)] -> ({cat: bps}, dominant cat)."""
    out: Dict[str, float] = {}
    for cat, bps in items:
        out[cat] = out.get(cat, 0.0) + bps
    dom = max(out.items(), key=lambda kv: kv[1])[0] if out else "other"
    return {k: round(v) for k, v in out.items()}, dom
