"""What is this device? A best guess, with the evidence for it, from everything MCC can see.

No single clue is reliable, so each one adds weight to what the device might be (its kind, brand, OS and
model) and the best-supported answer wins:

  * the MAC's vendor (IEEE registry, mcc/oui.py): who made the network chip. Decisive for single-purpose
    makers (Brother -> printer, Sonos -> speaker), only a hint for others (Apple, Samsung, Intel);
  * a private (randomized) MAC: phones, tablets and laptops hide their hardware address per Wi-Fi network;
  * the host name it sent with DHCP: "Janes-iPhone", "DESKTOP-4F1K2LQ", "BRW0080927AFBCE", "ESP_3A1F2C";
  * the DHCP vendor class, when the router reports it: "MSFT 5.0" is Windows, "android-dhcp-14" Android 14;
  * neighbor discovery (LLDP / CDP / MNDP): switches, access points, IP phones announce what they are;
  * the Wi-Fi registration table: whether it's a wireless client of the router;
  * its traffic: the names it looks up (captive.apple.com, connectivitycheck.gstatic.com, msftconnecttest.com,
    *.lgtvsdp.com, a2.tuyaus.com ...) and the services it offers (a host others print to on 9100 is a printer).

Traffic clues are remembered per MAC (data/fingerprints.json, 30 days), so a device that only phones home
once an hour is still recognised. MCC never probes or scans a device to identify it: everything here is read
from the router or from traffic that was already flowing.
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections import OrderedDict, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .classify import _matches

KINDS: List[Dict[str, str]] = [
    {"id": "phone", "label": "Phone"}, {"id": "tablet", "label": "Tablet"}, {"id": "computer", "label": "Computer"},
    {"id": "server", "label": "Server"}, {"id": "nas", "label": "NAS / file server"}, {"id": "tv", "label": "TV"},
    {"id": "streamer", "label": "Streaming player"}, {"id": "speaker", "label": "Smart speaker"},
    {"id": "console", "label": "Game console"}, {"id": "camera", "label": "Camera"},
    {"id": "printer", "label": "Printer"}, {"id": "smarthome", "label": "Smart home device"},
    {"id": "network", "label": "Network equipment"}, {"id": "voip", "label": "VoIP phone"},
    {"id": "wearable", "label": "Wearable"}, {"id": "car", "label": "Vehicle"}, {"id": "vm", "label": "Virtual machine"},
]
KIND_LABEL = {k["id"]: k["label"] for k in KINDS}

# What an Apple device runs, by kind
APPLE_OS = {"phone": "iOS", "tablet": "iPadOS", "computer": "macOS", "streamer": "tvOS", "speaker": "HomePod OS",
            "wearable": "watchOS"}
# "<brand> <noun>": "Brother printer", "Synology NAS"
NOUN = {"nas": "NAS", "tv": "TV", "voip": "VoIP phone", "smarthome": "smart-home device", "network": "network device",
        "vm": "virtual machine", "streamer": "streaming player", "speaker": "smart speaker", "console": "game console",
        "car": "vehicle"}
# A model name when we know the brand and the kind but nothing more specific
MODEL_OF = {("Apple", "phone"): "iPhone", ("Apple", "tablet"): "iPad", ("Apple", "computer"): "Mac",
            ("Apple", "streamer"): "Apple TV", ("Apple", "speaker"): "HomePod", ("Apple", "wearable"): "Apple Watch",
            ("Google", "streamer"): "Chromecast", ("Google", "speaker"): "Nest speaker", ("Google", "phone"): "Pixel",
            ("Amazon", "speaker"): "Echo", ("Amazon", "streamer"): "Fire TV", ("Amazon", "tablet"): "Fire tablet",
            ("Samsung", "phone"): "Galaxy phone", ("Samsung", "tablet"): "Galaxy Tab", ("Microsoft", "console"): "Xbox",
            ("Sony", "console"): "PlayStation", ("Nintendo", "console"): "Switch"}

# -- the MAC's vendor: (pattern on the registered name, brand, kinds it suggests, os, model) ------------------
# Kind weights: 4-5 for makers of one kind of thing, 1-2 where the maker builds many.
VENDORS: List[Tuple[str, str, str, str, str]] = [
    (r"^apple$", "Apple", "phone:1.5 computer:1 tablet:0.5", "", ""),
    (r"^routerboard", "MikroTik", "network:4", "RouterOS", ""),
    (r"^ubiquiti", "Ubiquiti", "network:4", "", ""),
    (r"^tp-?link", "TP-Link", "network:1.5 smarthome:1.5", "", ""),
    (r"^netgear", "Netgear", "network:3", "", ""),
    (r"^d-link", "D-Link", "network:3 camera:1", "", ""),
    (r"^zyxel", "Zyxel", "network:4", "", ""),
    (r"^eero$", "eero", "network:5", "", "eero mesh Wi-Fi"),
    (r"^(avm|fritz! technology)$", "AVM FRITZ!", "network:5", "", "FRITZ!Box"),
    (r"^(cisco-linksys|linksys|the linksys)", "Linksys", "network:4", "", ""),
    (r"^cisco meraki", "Cisco Meraki", "network:5", "", ""),
    (r"^cisco", "Cisco", "network:3 voip:1", "", ""),
    (r"^hewlett packard enterprise", "HPE Aruba", "network:3 server:1", "", ""),
    (r"^(ruckus|juniper|arista|extreme networks|fortinet|palo alto|cambium|engenius|mercusys|tenda|"
     r"gl technologies|sagemcom|arcadyan|technicolor|vantiva|commscope|arris|askey|fiberhome|calix|adtran|"
     r"actiontec|sercomm|plume design)", "", "network:4", "", ""),
    (r"^huawei technologies", "Huawei", "network:1.5 phone:1.5", "", ""),
    (r"^(huawei device|honor device)", "Huawei", "phone:3.5 tablet:1", "Android", ""),
    (r"^zte", "ZTE", "network:2 phone:1", "", ""),
    (r"^samsung electronics", "Samsung", "phone:1.5 tv:1 tablet:0.5", "", ""),
    (r"^google", "Google", "streamer:1.5 speaker:1 phone:1", "", ""),
    (r"^nest labs", "Google Nest", "smarthome:4", "", ""),
    (r"^blink by amazon", "Blink", "camera:5", "", ""),
    (r"^(amazon technologies|amazon\.com)$", "Amazon", "speaker:1.5 streamer:1 smarthome:1", "", ""),
    (r"^microsoft", "Microsoft", "computer:1.5 console:1", "", ""),
    (r"^sony (interactive|computer entertainment)", "Sony", "console:5", "", "PlayStation"),
    (r"^sony", "Sony", "tv:1.5 console:1 phone:0.5", "", ""),
    (r"^nintendo", "Nintendo", "console:5", "", ""),
    (r"^valve$", "Valve", "console:4", "SteamOS", "Steam Deck"),
    (r"^nvidia", "Nvidia", "streamer:1.5 computer:1", "", ""),
    (r"^roku", "Roku", "streamer:5", "Roku OS", ""),
    (r"^sonos$", "Sonos", "speaker:5", "", ""),
    (r"^(bose|harman|bang & olufsen|d&m holdings|sound united|onkyo|yamaha)", "", "speaker:4", "", ""),
    (r"^lg electronics", "LG", "tv:2 phone:0.5", "", ""),
    (r"^lg innotek", "LG", "tv:1 smarthome:1", "", ""),
    (r"^(vizio|tp vision|hisense|funai|tcl\b|shenzhen tcl|skyworth|shenzhen skyworth)", "", "tv:4", "", ""),
    (r"^(sharp|panasonic)", "", "tv:2", "", ""),
    (r"^raspberry pi", "Raspberry Pi", "computer:4", "Linux", "Raspberry Pi"),
    (r"^espressif", "Espressif", "smarthome:4", "", "ESP32/ESP8266 module"),
    (r"^tuya", "Tuya", "smarthome:5", "", ""),
    (r"^shelly", "Shelly", "smarthome:5", "", ""),
    (r"^(signify|philips lighting)", "Philips Hue", "smarthome:5", "", ""),
    (r"^(lifi labs|lutron|ecobee|the chamberlain group|irobot|beijing roborock|resideo|chengdu meross|leviton)",
     "", "smarthome:5", "", ""),
    (r"^belkin", "Belkin", "smarthome:2 network:1.5", "", ""),
    (r"^(gd midea|midea|haier|whirlpool|bsh hausger|miele|electrolux)", "", "smarthome:4", "", ""),
    (r"^ring$", "Ring", "camera:5", "", ""),
    (r"^(wyze|hangzhou hikvision|zhejiang dahua|amcrest|reolink|axis communications|arlo technology|hanwha|"
     r"vivotek|zhejiang uniview|hangzhou ezviz)", "", "camera:5", "", ""),
    (r"^(brother|seiko epson|xerox|lexmark|kyocera|ricoh|konica minolta|zebra technologies)", "", "printer:5", "", ""),
    (r"^canon", "Canon", "printer:4 camera:1", "", ""),
    (r"^(hp|hewlett packard)$", "HP", "printer:2 computer:2", "", ""),
    (r"^(synology|qnap|asustor|western digital)", "", "nas:5", "", ""),
    (r"^buffalo", "Buffalo", "nas:2 network:2", "", ""),
    (r"^(dell|lenovo|lcfc|acer|giga-byte|micro-star|asrock|elitegroup|framework computer)", "", "computer:4", "", ""),
    (r"^asustek", "ASUS", "computer:2 network:2", "", ""),
    (r"^intel", "Intel", "computer:3", "", ""),
    (r"^(super micro|inventec)", "", "server:3 computer:1", "", ""),
    (r"^(hon hai|cloud network technology|liteon|azurewave|quanta|wistron|pegatron|compal|universal global)",
     "", "computer:1.5", "", ""),
    (r"^realtek", "Realtek", "computer:1.5 smarthome:1", "", ""),
    (r"^(texas instruments|silicon laboratories|nordic semiconductor|microchip|shanghai high-flying|"
     r"beken|bouffalo|altobeam|shenzhen bilian|chongqing fugui)", "", "smarthome:2", "", ""),
    (r"^(amlogic|fuzhou rockchip|allwinner)", "", "streamer:3", "Android", ""),
    (r"^(xiaomi|beijing xiaomi)", "Xiaomi", "phone:2 smarthome:1.5", "", ""),
    (r"^(guangdong oppo|oppo)", "OPPO", "phone:4", "Android", ""),
    (r"^(vivo mobile|realme|oneplus|motorola|hmd global|tecno mobile|itel mobile|infinix|tct mobile|fairphone|"
     r"nothing technology|htc)", "", "phone:4", "Android", ""),
    (r"^(fitbit|garmin)", "", "wearable:4", "", ""),
    (r"^tesla$", "Tesla", "car:5", "", ""),
    (r"^(polycom|yealink|xiamen yealink|grandstream|snom|mitel|avaya)", "", "voip:5", "", ""),
    (r"^(vmware|xensource|parallels)", "", "vm:6", "", ""),
    (r"^pcs systemtechnik", "VirtualBox", "vm:6", "", "VirtualBox VM"),
]
# Brand names, tidied: the registry says "Hon Hai Precision Ind" and "Guangdong Oppo Mobile Telecommunications"
_BRAND_TIDY = [(r"^hon hai|^cloud network technology", "Foxconn"), (r"^giga-byte", "Gigabyte"),
               (r"^micro-star", "MSI"), (r"^elitegroup", "ECS"), (r"^lcfc", "Lenovo"), (r"^seiko epson", "Epson"),
               (r"^vivo mobile", "vivo"), (r"^motorola", "Motorola"), (r"^hmd global", "Nokia (HMD)"),
               (r"^tct mobile", "TCL / Alcatel"), (r"^tp vision", "Philips TV"), (r"^gd midea", "Midea"),
               (r"^bsh hausger", "Bosch / Siemens"), (r"^d&m holdings|^sound united", "Denon / Marantz"),
               (r"^super micro", "Supermicro"), (r"^western digital", "WD"), (r"^gl technologies", "GL.iNet"),
               (r"^xensource", "Xen"), (r"^lifi labs", "LIFX"), (r"^the chamberlain", "Chamberlain"),
               (r"^chengdu meross", "Meross"), (r"^nothing technology", "Nothing"), (r"^realme", "realme"),
               (r"^oneplus", "OnePlus"), (r"^xiamen yealink|^yealink", "Yealink"), (r"^qnap", "QNAP")]
# then, for any other name: drop a leading city / province and a trailing generic word
_PLACE = re.compile(r"^(hangzhou|shenzhen|zhejiang|beijing|shanghai|guangdong|xiamen|chengdu|fuzhou|chongqing|"
                    r"wuxi|dongguan|suzhou|nanjing|qingdao|sichuan|jiangsu|guangzhou|hefei|wuhan|tianjin) ", re.I)
_GENERIC = re.compile(r" (technology|technologies|tech|labs|innovation|international|electronics|communications?|industries|"
                      r"systems|software|group|digital technology|network technology|networks?|"
                      r"intelligent technology|smart|science and technology|manufacturing)$", re.I)
# Well-known virtual NICs (some are locally administered, so they'd otherwise look "random")
VM_PREFIXES = {"525400": "QEMU / KVM", "00155D": "Hyper-V", "0242": "Docker", "000C29": "VMware",
               "005056": "VMware", "000569": "VMware", "080027": "VirtualBox", "00163E": "Xen", "001C42": "Parallels"}

# -- host names: (pattern, weight, kind, brand, os, model) --------------------------------------------------
_W = r"(?<![a-z])"   # start of a word in a lower-cased host name
_E = r"(?![a-z])"    # end of one
HOSTNAMES: List[Tuple[str, float, str, str, str, str]] = [
    (r"iphone", 6, "phone", "Apple", "iOS", "iPhone"),
    (r"ipad", 6, "tablet", "Apple", "iPadOS", "iPad"),
    (r"macbook", 6, "computer", "Apple", "macOS", "MacBook"),
    (_W + r"imac" + _E, 6, "computer", "Apple", "macOS", "iMac"),
    (r"mac-?mini|macmini", 6, "computer", "Apple", "macOS", "Mac mini"),
    (r"mac-?(pro|studio)", 6, "computer", "Apple", "macOS", "Mac"),
    (r"apple-?tv|appletv", 6, "streamer", "Apple", "tvOS", "Apple TV"),
    (r"homepod", 6, "speaker", "Apple", "", "HomePod"),
    (r"apple-?watch", 6, "wearable", "Apple", "watchOS", "Apple Watch"),
    (r"galaxy-?tab|^sm-[tx]\d", 6, "tablet", "Samsung", "Android", "Galaxy Tab"),
    (r"galaxy|^sm-[asgnfmezr]\d", 5, "phone", "Samsung", "Android", "Galaxy phone"),
    (r"^android[-_][0-9a-f]{6,}", 4, "phone", "", "Android", ""),
    (r"pixel", 5, "phone", "Google", "Android", "Pixel"),
    (r"oneplus", 5, "phone", "OnePlus", "Android", ""),
    (r"^(redmi|poco)" + _E + r"|^mi-?\d|xiaomi", 4, "phone", "Xiaomi", "Android", ""),
    (r"^(huawei|honor)" + _E, 3, "phone", "", "Android", ""),
    (r"^(moto|motorola)" + _E, 4, "phone", "Motorola", "Android", ""),
    (r"^(oppo|vivo|realme)" + _E, 4, "phone", "", "Android", ""),
    (r"^desktop-[a-z0-9]{6,}$", 5, "computer", "", "Windows", ""),
    (r"^laptop-[a-z0-9]{6,}$", 5, "computer", "", "Windows", "Windows laptop"),
    (r"^win-[a-z0-9]{6,}$", 4, "server", "", "Windows", ""),
    (r"chromebook", 5, "computer", "", "ChromeOS", "Chromebook"),
    (r"^(esp|esp32|esp8266)[-_]", 4, "smarthome", "Espressif", "", "ESP32/ESP8266 module"),
    (r"^(tasmota|esphome|wled|shelly|sonoff|tuya|smartlife|lumi|meross|kasa|tapo|wemo|hs1\d\d|kp\d{3}|ep\d\d)"
     + _E, 5, "smarthome", "", "", ""),
    (r"^(chromecast|google-?tv)", 6, "streamer", "Google", "", "Chromecast"),
    (r"google-?home|google-?nest|nest-?(mini|hub|audio)", 6, "speaker", "Google", "", "Nest speaker"),
    (r"^nest" + _E + r"|thermostat|ecobee", 4, "smarthome", "", "", ""),
    (r"^echo" + _E + r"|^amazon-[0-9a-f]{6,}", 3, "speaker", "Amazon", "Fire OS", ""),
    (r"kindle", 6, "tablet", "Amazon", "Fire OS", "Kindle"),
    (r"fire-?tv|firestick", 6, "streamer", "Amazon", "Fire OS", "Fire TV"),
    (r"^roku", 6, "streamer", "Roku", "Roku OS", ""),
    (r"lgwebostv|lg-?webos|^\[lg\]", 6, "tv", "LG", "webOS", "webOS TV"),
    (r"samsung.?tv|^\[tv\]|tizen", 6, "tv", "Samsung", "Tizen", ""),
    (r"bravia", 6, "tv", "Sony", "", "Bravia"),
    (r"vizio|smartcast", 5, "tv", "Vizio", "", ""),
    (r"hisense|vidaa", 5, "tv", "Hisense", "", ""),
    (_W + r"tv" + _E + r"|television", 4, "tv", "", "", ""),
    (r"shield", 4, "streamer", "Nvidia", "Android TV", "Shield"),
    (r"xbox", 6, "console", "Microsoft", "", "Xbox"),
    (r"^ps[345]" + _E + r"|playstation", 6, "console", "Sony", "", "PlayStation"),
    (r"nintendo", 6, "console", "Nintendo", "", "Switch"),
    (r"steam-?deck", 6, "console", "Valve", "SteamOS", "Steam Deck"),
    (r"^(hp|npi)[0-9a-f]{6}$|officejet|laserjet|deskjet|^hp-?print", 6, "printer", "HP", "", ""),
    (r"^br[nw][0-9a-f]{12}$|brother", 6, "printer", "Brother", "", ""),
    (r"^epson|^et-\d{4}", 6, "printer", "Epson", "", ""),
    (r"^canon|^cnm[fp]|pixma|imageclass", 5, "printer", "Canon", "", ""),
    (r"xerox|lexmark|kyocera|ricoh", 5, "printer", "", "", ""),
    (r"^(octopi|prusa|bambu|voron|klipper|mainsail|fluidd)", 5, "printer", "", "", "3D printer"),
    (r"print", 4, "printer", "", "", ""),
    (r"raspberrypi|^rpi" + _E + r"|^pi-|^pi\d" + _E, 5, "computer", "Raspberry Pi", "Linux", "Raspberry Pi"),
    (r"^(diskstation|ds\d{3,4}|rs\d{3,4})" + _E + r"|synology", 6, "nas", "Synology", "DSM", ""),
    (r"qnap|^ts-\d{3}", 6, "nas", "QNAP", "QTS", ""),
    (r"truenas|freenas|unraid|openmediavault|" + _W + r"nas" + _E, 4, "nas", "", "", ""),
    (r"^ring" + _E + r"|ringdoorbell", 5, "camera", "Ring", "", "doorbell"),
    (r"wyze", 5, "camera", "Wyze", "", ""),
    (r"doorbell", 5, "camera", "", "", "doorbell"),
    (r"(ipcam|webcam|camera|" + _W + r"cam" + _E + r"|" + _W + r"ipc" + _E + r"|" + _W + r"[dn]vr" + _E + r")",
     4, "camera", "", "", ""),
    (r"^philips-?hue|^hue-?bridge", 6, "smarthome", "Philips Hue", "", "Hue Bridge"),
    (r"sonos", 6, "speaker", "Sonos", "", ""),
    (r"^(unifi|uap|u6-|u7-|usw|udm|uck|ubnt)", 5, "network", "Ubiquiti", "", ""),
    (r"mikrotik|routerboard|^rb\d|^crs\d|^css\d|^hap" + _E + r"|^cap-", 5, "network", "MikroTik", "", ""),
    (r"^(eero|orbi|deco|velop|google-?wifi|nest-?wifi|fritz)", 5, "network", "", "", ""),
    (r"router|switch|^ap" + _E + r"|access-?point|extender|repeater|mesh", 3, "network", "", "", ""),
    (r"tesla", 5, "car", "Tesla", "", ""),
    (r"(laptop|notebook|thinkpad|latitude|" + _W + r"xps" + _E + r"|surface|zenbook|vivobook|ideapad|"
     r"elitebook|probook)", 4, "computer", "", "", ""),
    (r"desktop|workstation|^pc[-_]|[-_]pc$|gaming", 3, "computer", "", "", ""),
    (_W + r"(phone|mobile)" + _E, 3, "phone", "", "", ""),
    (_W + r"(tablet|tab)" + _E, 3, "tablet", "", "", ""),
    (r"homeassistant|home-assistant|hassio", 5, "smarthome", "", "Home Assistant OS", "Home Assistant hub"),
    (r"server|homelab|proxmox|" + _W + r"pve" + _E + r"|esxi|docker|k8s|kube", 3, "server", "", "", ""),
    (r"watch" + _E + r"|fitbit|garmin", 3, "wearable", "", "", ""),
    (r"vacuum|roomba|roborock|deebot", 5, "smarthome", "", "", "robot vacuum"),
    (_W + r"(plug|bulb|light|lamp|blinds|fan|heater|purifier)" + _E, 3, "smarthome", "", "", ""),
    (r"^(kali|ubuntu|debian|fedora|arch|linux|raspbian|alpine)" + _E, 3, "computer", "", "Linux", ""),
]

# -- DHCP vendor class (option 60): (pattern, weight, kind, brand, os, model); {1} = first regex group ---------
DHCP_CLASSES: List[Tuple[str, float, str, str, str, str]] = [
    (r"^msft 5\.0", 4, "computer", "", "Windows", ""),
    (r"^msft", 4, "computer", "", "Windows", ""),
    (r"^android-dhcp-(\d+)", 4, "phone", "", "Android {1}", ""),
    (r"^huawei:android", 4, "phone", "Huawei", "Android", ""),
    (r"^dhcpcd-[\d.]+:linux-[^:]+:[^:]+:bcm2", 4, "computer", "Raspberry Pi", "Linux", "Raspberry Pi"),
    (r"^dhcpcd.*android", 4, "phone", "", "Android", ""),
    (r"^dhcpcd", 2, "", "", "Linux", ""),
    (r"^udhcp", 2, "smarthome", "", "Embedded Linux", ""),
    (r"^ubnt", 5, "network", "Ubiquiti", "", ""),
    (r"^mikrotik", 5, "network", "MikroTik", "RouterOS", ""),
    (r"^cisco", 4, "network", "Cisco", "", ""),
    (r"^(polycom|yealink|grandstream|snom|aastra|mitel)", 5, "voip", "", "", ""),
    (r"^(brother|canon|epson|hewlett-packard|hp |xerox|lexmark)", 5, "printer", "", "", ""),
    (r"^axis", 5, "camera", "Axis", "", ""),
    (r"^(linux|anaconda)", 2, "", "", "Linux", ""),
]

# -- names looked up: (name fragment, weight, kind, brand, os, model, what it means) --------------------------
# Fragments match like traffic types do (mcc/classify.py): a domain and its subdomains, or a bare word anywhere.
NAME_HINTS: List[Tuple[str, float, str, str, str, str, str]] = [
    ("captive.apple.com", 3, "", "Apple", "Apple", "", "Apple's captive-portal check"),
    ("push.apple.com", 2.5, "", "Apple", "Apple", "", "Apple push notifications"),
    ("mesu.apple.com", 2.5, "", "Apple", "Apple", "", "Apple software update check"),
    ("icloud.com", 1.5, "", "Apple", "Apple", "", "iCloud"),
    ("apple.com", 1, "", "Apple", "", "", "Apple services"),
    ("connectivitycheck.gstatic.com", 3, "phone:1", "", "Android", "", "Android's connectivity check"),
    ("connectivitycheck.android.com", 3, "phone:1", "", "Android", "", "Android's connectivity check"),
    ("android.clients.google.com", 3, "phone:1", "", "Android", "", "Google Play services"),
    ("play.googleapis.com", 2, "phone:1", "", "Android", "", "Google Play"),
    ("msftconnecttest.com", 3, "computer:1", "", "Windows", "", "Windows' connectivity check"),
    ("msftncsi.com", 3, "computer:1", "", "Windows", "", "Windows' connectivity check"),
    ("settings-win.data.microsoft.com", 3, "computer:1", "", "Windows", "", "Windows telemetry"),
    ("windowsupdate.com", 2, "computer:1", "", "Windows", "", "Windows Update"),
    ("xboxlive.com", 3, "console", "Microsoft", "", "Xbox", "Xbox Live"),
    ("playstation.net", 3, "console", "Sony", "", "PlayStation", "PlayStation Network"),
    ("nintendo.net", 3, "console", "Nintendo", "", "Switch", "Nintendo services"),
    ("roku.com", 3, "streamer", "Roku", "Roku OS", "", "Roku services"),
    ("lgtvsdp.com", 4, "tv", "LG", "webOS", "webOS TV", "LG TV services"),
    ("lgappstv.com", 3, "tv", "LG", "webOS", "webOS TV", "LG TV app store"),
    ("lgsmartad.com", 3, "tv", "LG", "webOS", "webOS TV", "LG TV ads"),
    ("samsungcloudsolution.com", 3, "tv", "Samsung", "Tizen", "", "Samsung TV services"),
    ("samsungotn.net", 3, "tv", "Samsung", "Tizen", "", "Samsung TV updates"),
    ("samsungacr.com", 3, "tv", "Samsung", "Tizen", "", "Samsung TV content recognition"),
    ("vizio.com", 3, "tv", "Vizio", "", "", "Vizio TV services"),
    ("sonos.com", 4, "speaker", "Sonos", "", "", "Sonos services"),
    ("amazonalexa.com", 3, "speaker", "Amazon", "Fire OS", "Echo", "Alexa"),
    ("avs-alexa", 3, "speaker", "Amazon", "Fire OS", "Echo", "Alexa voice service"),
    ("fireoscaptiveportal.com", 4, "", "Amazon", "Fire OS", "", "Fire OS connectivity check"),
    ("kindle-time.amazon.com", 4, "tablet", "Amazon", "Fire OS", "Kindle", "Kindle clock sync"),
    ("ring.com", 3, "camera", "Ring", "", "", "Ring cloud"),
    ("dropcam.com", 4, "camera", "Google Nest", "", "Nest Cam", "Nest Cam cloud"),
    ("nest.com", 3, "smarthome", "Google Nest", "", "", "Nest cloud"),
    ("meethue.com", 4, "smarthome", "Philips Hue", "", "", "Philips Hue cloud"),
    ("tuya", 4, "smarthome", "Tuya", "", "", "Tuya smart-home cloud"),
    ("wyze", 3, "camera", "Wyze", "", "", "Wyze cloud"),
    ("ezvizlife.com", 4, "camera", "Ezviz", "", "", "Ezviz camera cloud"),
    ("hik-connect.com", 4, "camera", "Hikvision", "", "", "Hik-Connect camera cloud"),
    ("easy4ipcloud.com", 4, "camera", "Dahua", "", "", "Dahua camera cloud"),
    ("amcrestcloud.com", 4, "camera", "Amcrest", "", "", "Amcrest camera cloud"),
    ("arlo.com", 4, "camera", "Arlo", "", "", "Arlo camera cloud"),
    ("immedia-semi.com", 4, "camera", "Blink", "", "", "Blink camera cloud"),
    ("eufylife.com", 3, "camera", "eufy", "", "", "eufy cloud"),
    ("ecobee.com", 4, "smarthome", "ecobee", "", "thermostat", "ecobee cloud"),
    ("myq-cloud.com", 4, "smarthome", "Chamberlain", "", "myQ garage opener", "myQ cloud"),
    ("tplinkcloud.com", 3, "smarthome", "TP-Link", "", "", "TP-Link Kasa cloud"),
    ("ewelink", 4, "smarthome", "Sonoff", "", "", "eWeLink (Sonoff) cloud"),
    ("shelly.cloud", 4, "smarthome", "Shelly", "", "", "Shelly cloud"),
    ("roborock", 4, "smarthome", "Roborock", "", "robot vacuum", "Roborock cloud"),
    ("irobot", 4, "smarthome", "iRobot", "", "Roomba", "iRobot cloud"),
    ("io.mi.com", 3, "smarthome", "Xiaomi", "", "", "Xiaomi smart-home cloud"),
    ("miui.com", 3, "phone", "Xiaomi", "Android", "", "MIUI services"),
    ("hicloud.com", 2, "phone", "Huawei", "Android", "", "Huawei cloud"),
    ("home-assistant.io", 3, "smarthome", "", "Home Assistant OS", "Home Assistant hub", "Home Assistant"),
    ("nabu.casa", 3, "smarthome", "", "Home Assistant OS", "Home Assistant hub", "Home Assistant Cloud"),
    ("ui.com", 3, "network", "Ubiquiti", "", "", "Ubiquiti cloud"),
    ("ubnt.com", 3, "network", "Ubiquiti", "", "", "Ubiquiti cloud"),
    ("mikrotik.com", 3, "network", "MikroTik", "RouterOS", "", "MikroTik updates"),
    ("synology.com", 3, "nas", "Synology", "DSM", "", "Synology services"),
    ("quickconnect.to", 4, "nas", "Synology", "DSM", "", "Synology QuickConnect"),
    ("myqnapcloud.com", 4, "nas", "QNAP", "QTS", "", "myQNAPcloud"),
    ("hpeprint.com", 4, "printer", "HP", "", "", "HP ePrint"),
    ("epsonconnect.com", 4, "printer", "Epson", "", "", "Epson Connect"),
    ("bambulab.com", 4, "printer", "Bambu Lab", "", "3D printer", "Bambu Lab cloud"),
    ("teslamotors.com", 4, "car", "Tesla", "", "", "Tesla services"),
    ("tesla.services", 4, "car", "Tesla", "", "", "Tesla services"),
    ("fitbit.com", 3, "wearable", "Fitbit", "", "", "Fitbit sync"),
    ("raspberrypi.org", 3, "computer", "Raspberry Pi", "Linux", "Raspberry Pi", "Raspberry Pi OS updates"),
    ("raspberrypi.com", 3, "computer", "Raspberry Pi", "Linux", "Raspberry Pi", "Raspberry Pi OS updates"),
    ("debian.org", 2, "", "", "Linux", "", "Debian packages"),
    ("ubuntu.com", 2, "", "", "Linux", "", "Ubuntu packages"),
    ("fedoraproject.org", 2, "", "", "Linux", "", "Fedora packages"),
    ("archlinux.org", 2, "", "", "Linux", "", "Arch packages"),
]

# -- services a device offers (it answers on these ports): port -> (weight, kind, brand, os, model, what) ------
SERVES: Dict[int, Tuple[float, str, str, str, str, str]] = {
    631: (4, "printer", "", "", "", "IPP printing"), 9100: (4, "printer", "", "", "", "raw printing (JetDirect)"),
    515: (3, "printer", "", "", "", "LPD printing"), 554: (3, "camera", "", "", "", "an RTSP video stream"),
    8009: (3, "streamer", "Google", "", "Chromecast", "Google Cast"), 62078: (4, "phone", "Apple", "iOS", "", "iOS device sync"),
    445: (2, "nas", "", "", "", "SMB file sharing"), 548: (2, "nas", "", "", "", "AFP file sharing"),
    2049: (2, "nas", "", "", "", "NFS"), 5000: (1.5, "nas", "", "", "", "a NAS admin page (5000)"),
    5001: (1.5, "nas", "", "", "", "a NAS admin page (5001)"), 32400: (2, "server", "", "", "", "Plex Media Server"),
    22: (1.5, "server", "", "", "", "SSH"), 3389: (3, "computer", "", "Windows", "", "Remote Desktop"),
    5900: (1.5, "computer", "", "", "", "VNC"), 8123: (4, "smarthome", "", "Home Assistant OS", "Home Assistant hub",
                                                        "Home Assistant"),
    1883: (2, "server", "", "", "", "an MQTT broker"), 53: (2, "server", "", "", "", "DNS (Pi-hole, AdGuard ...)"),
    80: (1, "server", "", "", "", "a web server"), 443: (1, "server", "", "", "", "a web server"),
}
# -- ports it connects out to: (proto, port) -> (weight, kind, brand, os, model, what) -------------------------
CONNECTS: Dict[Tuple[str, int], Tuple[float, str, str, str, str, str]] = {
    ("TCP", 5223): (1.5, "", "Apple", "Apple", "", "Apple push (5223)"),
    ("TCP", 5228): (1, "phone:0.5", "", "Android", "", "Google push (5228)"),
    ("TCP", 8883): (2, "smarthome", "", "", "", "MQTT over TLS to a cloud (8883)"),
    ("TCP", 1883): (2, "smarthome", "", "", "", "MQTT to a cloud (1883)"),
    ("UDP", 3074): (2, "console", "", "", "", "Xbox Live (3074)"),
    ("TCP", 3074): (2, "console", "", "", "", "Xbox Live (3074)"),
}

KEEP_S = 30 * 86400
SAVE_EVERY_S = 60.0
MAX_HINTS = 40


def _kinds(spec: str, weight: float) -> Dict[str, float]:
    """'phone:1.5 computer:1' -> {...}; a bare 'printer' takes `weight`."""
    out: Dict[str, float] = {}
    for part in (spec or "").split():
        k, _, w = part.partition(":")
        out[k] = float(w) if w else weight
    return out


_VENDOR_RX = [(re.compile(p, re.I), b, _kinds(k, 0), o, m) for p, b, k, o, m in VENDORS]
_TIDY_RX = [(re.compile(p, re.I), b) for p, b in _BRAND_TIDY]
_HOST_RX = [(re.compile(p), w, k, b, o, m) for p, w, k, b, o, m in HOSTNAMES]
_DHCP_RX = [(re.compile(p, re.I), w, k, b, o, m) for p, w, k, b, o, m in DHCP_CLASSES]


def brand_of(vendor: str) -> str:
    """A registered vendor name -> the brand people know it by."""
    for rx, brand in _TIDY_RX:
        if rx.search(vendor):
            return brand
    for rx, brand, _k, _o, _m in _VENDOR_RX:
        if brand and rx.search(vendor):
            return brand
    short = _PLACE.sub("", vendor).strip() or vendor
    for _ in range(2):
        trimmed = _GENERIC.sub("", short)
        if trimmed == short or not trimmed.strip():
            break
        short = trimmed
    return short.strip() or vendor


def clue(source: str, text: str, w: float, kind: str = "", brand: str = "", os: str = "", model: str = "",
         bw: Optional[float] = None) -> Dict[str, Any]:
    return {"source": source, "text": text, "w": w, "kinds": _kinds(kind, w), "brand": brand,
            "bw": w if bw is None else bw, "os": os, "model": model}


# -- the clues, one function per source ------------------------------------------------------------------------
def mac_clues(mac: str, vendor: Dict[str, Any]) -> List[Dict[str, Any]]:
    h = "".join(c for c in mac.upper() if c in "0123456789ABCDEF")
    for prefix, what in VM_PREFIXES.items():
        if h.startswith(prefix):
            return [clue("mac", "MAC prefix {} is a {} virtual network card".format(_colons(prefix), what), 6, "vm",
                         model="Docker container" if what == "Docker" else what + " VM")]
    if vendor.get("random"):
        return [clue("mac", "Private (randomized) MAC address: the device made it up, to hide its hardware "
                            "address on this network. Phones, tablets and laptops do this by default", 0,
                     "phone:2 tablet:1 computer:1")]
    name = vendor.get("vendor")
    if not name:
        return [clue("mac", "MAC prefix {} isn't in the IEEE registry".format(_colons(h[:6])), 0)] if len(h) == 12 else []
    if name.lower() == "private":
        return [clue("mac", "MAC prefix {} is registered privately: its maker chose not to publish its name".format(
            vendor.get("prefix", "")), 0)]
    out = []
    for rx, brand, kinds, os, model in _VENDOR_RX:
        if rx.search(name):
            c = clue("mac", "MAC vendor: {} ({}, IEEE {})".format(name, vendor.get("prefix", ""),
                                                                   vendor.get("registry", "")),
                     max(kinds.values()) if kinds else 0, brand=brand_of(name), os=os, model=model, bw=3)
            c["kinds"] = dict(kinds)
            out.append(c)
            break
    if not out:
        out.append(clue("mac", "MAC vendor: {} ({}, IEEE {})".format(name, vendor.get("prefix", ""),
                                                                      vendor.get("registry", "")), 0,
                        brand=brand_of(name), bw=3))
    return out


def name_clues(name: str, source: str) -> List[Dict[str, Any]]:
    n = (name or "").strip().lower()
    if not n:
        return []
    out, seen = [], set()
    for rx, w, kind, brand, os, model in _HOST_RX:
        if rx.search(n):
            key = (kind, brand, os, model)
            if key in seen:
                continue
            seen.add(key)
            what = model or (brand + " " if brand else "") + KIND_LABEL.get(kind, kind).lower()
            out.append(clue(source, "{} “{}” suggests {}".format(
                "Host name" if source == "hostname" else "Its name", name, _a(what)),
                w if source == "hostname" else w + 1, kind, brand, os, model))
    return out


def dhcp_clues(class_id: str) -> List[Dict[str, Any]]:
    s = (class_id or "").strip()
    if not s:
        return []
    for rx, w, kind, brand, os, model in _DHCP_RX:
        m = rx.search(s)
        if m:
            os = os.replace("{1}", m.group(1)) if m.groups() else os
            return [clue("dhcp", "DHCP vendor class “{}”: {}".format(s, os or brand or KIND_LABEL.get(kind, "")),
                         w, kind, brand, os, model)]
    return [clue("dhcp", "DHCP vendor class “{}”".format(s), 0)]


def neighbor_clues(n: Dict[str, Any]) -> List[Dict[str, Any]]:
    """An /ip/neighbor entry: the device announced itself over LLDP, CDP or MikroTik's MNDP."""
    if not n:
        return []
    platform, board, version = n.get("platform", ""), n.get("board", ""), n.get("version", "")
    desc, caps, ident = n.get("system-description", ""), n.get("system-caps-enabled") or n.get("system-caps", ""), \
        n.get("identity", "")
    by = n.get("discovered-by", "") or "neighbor discovery"
    said = ", ".join(x for x in (ident, platform, board, version, desc) if x)
    out = []
    if platform.lower().startswith("mikrotik"):
        ver = version.split()[0] if version else ""
        swos = "swos" in (version + desc).lower() or (ver[:1].isdigit() and int(ver.split(".")[0] or 0) < 3)
        os = ("SwOS" if swos else "RouterOS") + (" " + ver if ver else "")
        out.append(clue("neighbor", "Announces itself over {}: {}".format(by, said), 8, "network", "MikroTik",
                        os, board or ""))
        return out
    caps_l = caps.lower()
    kind = "voip" if "telephone" in caps_l else "network" if any(
        c in caps_l for c in ("bridge", "router", "wlan-ap", "repeater", "docsis")) else ""
    brand = ""
    for rx, b, _k, _o, _m in _VENDOR_RX:
        if b and (rx.search(platform) or rx.search(desc)):
            brand = b
            break
    out.append(clue("neighbor", "Announces itself over {}: {}{}".format(by, said, " (capabilities: {})".format(caps)
                                                                         if caps else ""),
                    7 if kind else 2, kind, brand, _os_from(platform + " " + desc), _model_from(board, platform, desc)))
    for c in name_clues(ident, "neighbor") + name_clues(desc, "neighbor"):
        c["w"] += 1
        c["kinds"] = {k: w + 1 for k, w in c["kinds"].items()}
        out.append(c)
    return out


def wifi_clues(w: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not w:
        return []
    bits = [x for x in (w.get("ssid"), w.get("band"), "signal {}".format(w["signal"]) if w.get("signal") else "") if x]
    return [clue("wifi", "Wi-Fi client of {}{}".format(w.get("interface") or "the router",
                                                       " ({})".format(", ".join(bits)) if bits else ""), 0)]


def hint_for_name(name: str) -> Optional[Tuple[str, str]]:
    """A looked-up name -> (hint key, the name), for names that say something about the device; else None."""
    n = (name or "").lower().rstrip(".")
    for frag, *_ in NAME_HINTS:
        if _matches(n, frag):
            return "name:" + frag, n
    return None


_NAME_HINT = {h[0]: h for h in NAME_HINTS}


def hint_clue(key: str, example: str) -> Optional[Dict[str, Any]]:
    kind_, _, arg = key.partition(":")
    if kind_ == "name" and arg in _NAME_HINT:
        _f, w, kind, brand, os, model, what = _NAME_HINT[arg]
        return clue("traffic", "Looked up {} ({})".format(example or arg, what), w, kind, brand, os, model)
    if kind_ in ("serve", "serve-wan") and arg.isdigit() and int(arg) in SERVES:
        w, kind, brand, os, model, what = SERVES[int(arg)]
        where = "to the Internet (port forward)" if kind_ == "serve-wan" else "on the LAN"
        return clue("service", "Offers {} {}: {}".format(what, where, example), w, kind, brand, os, model)
    if kind_ == "port":
        proto, _, port = arg.partition("/")
        h = CONNECTS.get((proto, int(port) if port.isdigit() else -1))
        if h:
            w, kind, brand, os, model, what = h
            return clue("traffic", "Connects out on {}{}".format(what, ": " + example if example else ""), w, kind,
                        brand, os, model)
    return None


# -- putting it together ---------------------------------------------------------------------------------------
def identify(dev: Dict[str, Any], vendor: Dict[str, Any], hints: Iterable[Tuple[str, str]] = (),
             neighbor: Optional[Dict[str, Any]] = None, wifi: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """dev: a device record (mac, hostname, name, class_id); vendor: MacVendors.lookup(mac);
    hints: [(hint key, example)] from its traffic. -> the best guess and every clue behind it."""
    clues: List[Dict[str, Any]] = []
    clues += mac_clues(dev.get("mac", ""), vendor)
    clues += neighbor_clues(neighbor or {})
    clues += name_clues(dev.get("hostname", ""), "hostname")
    label = (dev.get("name") or "").strip()
    if label and label.lower() != (dev.get("hostname") or "").strip().lower():
        clues += name_clues(label, "label")
    clues += dhcp_clues(dev.get("class_id", ""))
    clues += wifi_clues(wifi or {})
    for key, example in hints:
        c = hint_clue(key, example)
        if c:
            clues.append(c)
    return decide(clues, random=bool(vendor.get("random")), vendor=vendor.get("vendor", ""),
                  wifi=bool(wifi))


def decide(clues: List[Dict[str, Any]], random: bool = False, vendor: str = "", wifi: bool = False) -> Dict[str, Any]:
    kinds: Dict[str, float] = defaultdict(float)
    brands: Dict[str, float] = defaultdict(float)
    oses: Dict[str, float] = defaultdict(float)
    models: Dict[str, float] = defaultdict(float)
    for c in clues:
        for k, w in c["kinds"].items():
            if k:
                kinds[k] += w
        if c["brand"]:
            brands[c["brand"]] += c["bw"]
        if c["os"]:
            oses[c["os"]] += max(c["w"], 1)
        if c["model"]:
            models[c["model"]] += max(c["w"], 1)
    top = lambda d: max(d.items(), key=lambda kv: kv[1]) if d else ("", 0.0)  # noqa: E731
    kind, ks = top(kinds)
    if ks < 2:
        kind = ""
    brand, _ = top(brands)
    os, os_s = top(oses)
    if os_s < 2:
        os = ""
    # an OS name that is more specific wins over the generic one it refines ("Android 14" over "Android")
    for o in sorted(oses, key=len, reverse=True):
        if os and o != os and o.startswith(os) and oses[o] >= 2:
            os = o
            break
    if os == "Apple" or (brand == "Apple" and not os):
        os = APPLE_OS.get(kind, "iOS / macOS")
    model, ms = top(models)
    if ms < 2:
        model = ""
    if not model and kind:
        model = MODEL_OF.get((brand, kind), "")
    if model and brand and brand.lower() not in model.lower() and model[0].isupper():
        name = "{} {}".format(brand, model)
    elif model:
        name = (brand + " " if brand and not model[0].isupper() else "") + model
        name = name[0].upper() + name[1:]
    elif kind and brand:
        name = "{} {}".format(brand, NOUN.get(kind, KIND_LABEL[kind].lower()))
    elif kind and os and kind in ("phone", "tablet", "computer", "server", "tv", "streamer"):
        name = "{} {}".format(os.split()[0] if os.split()[0] not in ("Embedded",) else os, NOUN.get(kind, kind))
    elif kind:
        name = KIND_LABEL[kind]
    elif brand:
        name = "{} device".format(brand)
    elif os:
        name = "{} device".format(os)
    else:
        name = "Unknown device"
    if random and not brand and kind != "vm":
        name = "Private-address device" if name == "Unknown device" else name + " (private address)"
    score = max(ks, ms)
    confidence = "high" if score >= 7 else "medium" if score >= 4 else "low" if (kind or brand or os) else "none"
    clues.sort(key=lambda c: -c["w"])
    return {"label": name, "kind": kind, "kind_label": KIND_LABEL.get(kind, ""), "brand": brand, "os": os,
            "model": model, "vendor": vendor, "random": random, "wifi": wifi, "confidence": confidence,
            "score": round(score, 1),
            "clues": [{"source": c["source"], "text": c["text"], "w": round(c["w"], 1)} for c in clues]}


_OS_RX = re.compile(r"linux|windows|freebsd|openbsd|darwin|mac os", re.I)


def _os_from(text: str) -> str:
    m = _OS_RX.search(text)
    return {"darwin": "macOS", "mac os": "macOS"}.get(m.group(0).lower(), m.group(0).capitalize()) if m else ""


def _model_from(board: str, platform: str, desc: str) -> str:
    """A model name from what a neighbor announced: its board, or a platform / description naming one
    ("Cisco IP Phone 8841", "Ubiquiti U6-Lite, 6.6.65" -> "Ubiquiti U6-Lite")."""
    for text in (board, platform, desc.split(",")[0]):
        text = text.strip()
        if text and re.search(r"\d", text) and len(text) <= 40 and not _OS_RX.search(text):
            return text
    return ""


def _colons(h: str) -> str:
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def _a(what: str) -> str:
    what = what.strip()
    return ("an " if what[:1].lower() in tuple("aeiou") else "a ") + what if what else "a device"


# -- per-device memory of what its traffic revealed -----------------------------------------------------------
class Fingerprints:
    """MAC -> {hint key: [example, last seen]}, kept in data/fingerprints.json for 30 days."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = Path(data_dir)
        self.path = self.data_dir / "fingerprints.json"
        self.lock = threading.Lock()
        self.by_mac: Dict[str, Dict[str, List[Any]]] = {}
        self._dirty = False
        self._saved_at = time.time()
        self._name_cache: "OrderedDict[str, Optional[Tuple[str, str]]]" = OrderedDict()
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            now = time.time()
            for mac, hints in (data or {}).items():
                keep = {k: v for k, v in (hints or {}).items()
                        if isinstance(v, list) and len(v) == 2 and now - float(v[1]) < KEEP_S}
                if keep:
                    self.by_mac[str(mac).upper()] = keep
        except (OSError, ValueError, TypeError, AttributeError):
            pass

    def _name_hint(self, name: str) -> Optional[Tuple[str, str]]:
        if name in self._name_cache:
            return self._name_cache[name]
        h = hint_for_name(name)
        self._name_cache[name] = h
        if len(self._name_cache) > 5000:
            self._name_cache.popitem(last=False)
        return h

    def observe(self, mac_of: Dict[str, str], conns: Iterable[Dict[str, Any]], name_of: Any,
                now: Optional[float] = None, router: Iterable[str] = ()) -> None:
        """conns: normalised connections (local, remote, dir, proto, port). mac_of: LAN address -> MAC."""
        now = now or time.time()
        router = set(router)
        found: List[Tuple[str, str, str]] = []
        for c in conns:
            local, remote, d = c.get("local", ""), c.get("remote", ""), c.get("dir", "")
            port, proto = int(c.get("port") or 0), str(c.get("proto", ""))
            if d == "out":
                mac = mac_of.get(local)
                if not mac:
                    continue
                name = name_of(remote)
                h = self._name_hint(name) if name else None
                if h:
                    found.append((mac, h[0], h[1]))
                if (proto, port) in CONNECTS:
                    found.append((mac, "port:{}/{}".format(proto, port), name or remote))
            elif d == "in":  # dst-nat'ed to it: it serves this to the Internet
                mac = mac_of.get(local)
                if mac and port in SERVES:
                    found.append((mac, "serve-wan:{}".format(port), "{}/{}".format(proto.lower(), port)))
            elif d == "lan" and remote not in router:  # another LAN host connected to it
                mac = mac_of.get(remote)
                if mac and port in SERVES:
                    found.append((mac, "serve:{}".format(port), "{}/{} from {}".format(proto.lower(), port, local)))
        if not found:
            return
        with self.lock:
            for mac, key, example in found:
                hints = self.by_mac.setdefault(mac, {})
                prev = hints.get(key)
                if prev is None or now - prev[1] > 300:
                    hints[key] = [example, round(now)]
                    self._dirty = True
                if len(hints) > MAX_HINTS:
                    for k, _ in sorted(hints.items(), key=lambda kv: kv[1][1])[:len(hints) - MAX_HINTS]:
                        del hints[k]
        if now - self._saved_at >= SAVE_EVERY_S:
            self.save()

    def hints(self, mac: str) -> List[Tuple[str, str]]:
        with self.lock:
            return [(k, v[0]) for k, v in sorted(self.by_mac.get(mac.upper(), {}).items(), key=lambda kv: -kv[1][1])]

    def save(self) -> None:
        with self.lock:
            if not self._dirty:
                return
            now = time.time()
            for mac in list(self.by_mac):
                self.by_mac[mac] = {k: v for k, v in self.by_mac[mac].items() if now - v[1] < KEEP_S}
                if not self.by_mac[mac]:
                    del self.by_mac[mac]
            data = json.dumps(self.by_mac)
            self._dirty = False
            self._saved_at = now
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(data, encoding="utf-8")
            tmp.replace(self.path)
        except OSError:
            pass
