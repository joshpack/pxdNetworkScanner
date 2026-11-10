namespace pxdNetworkScanner.Core;

/// <summary>
/// Guesses what a device is from everything it gave away: the maker of its network card, its open ports, what it says
/// over UPnP, Bonjour, SNMP and its web page, its names and the TTL of its ping answer. Each guess keeps its reasons.
/// </summary>
public static class Classifier
{
    private static readonly string[] PrinterWords = ["printer", "laserjet", "officejet", "deskjet", "designjet", "pagewide", "envy ", "smart tank", "mfc-", "hl-l", "hl-", "dcp-", "imageclass", "imagerunner", "pixma", "maxify", "ecotank", "workforce", "expression home", "ecosys", "taskalfa", "bizhub", "lexmark", "xerox", "versalink", "workcentre", "ricoh", "aficio", "phaser", "zebra", "jetdirect", "brother nc-"];
    private static readonly string[] PrinterMakers = ["brother", "canon", "seiko epson", "epson", "lexmark", "xerox", "kyocera", "ricoh", "konica", "zebra", "oki", "sharp", "hp inc", "hewlett packard"];
    private static readonly string[] ConsoleWords = ["xbox", "playstation", "nintendo", "sony interactive"];
    private static readonly string[] NasWords = ["synology", "diskstation", "qnap", "asustor", "truenas", "freenas", "unraid", "terramaster", "readynas", "my cloud", "wd mycloud"];
    private static readonly string[] CameraWords = ["hikvision", "dahua", "reolink", "amcrest", "axis communications", "ip camera", "ipcam", "network camera", "nvr", "wyze", "arlo", "foscam", "lorex", "swann", "eufy", "doorbell", "unifi protect"];
    private static readonly string[] TvWords = ["smart tv", " tv", "tv ", "bravia", "webos", "tizen", "vizio", "smartcast", "roku", "fire tv", "firetv", "apple tv", "chromecast", "google tv", "android tv", "shield", "mediarenderer", "dlna", "sonos", "denon", "yamaha", "heos", "bose", "soundbar", "receiver"];
    private static readonly string[] NetMakers = ["ubiquiti", "mikrotik", "routerboard", "netgear", "tp-link", "cisco", "aruba", "ruckus", "eero", "linksys", "zyxel", "d-link", "juniper", "meraki", "fortinet", "netgate", "draytek", "tenda", "mercusys", "edgecore", "extreme networks", "cambium", "grandstream", "asus router", "quectel", "sierra wireless", "telit", "inseego", "franklin wireless"];
    private static readonly string[] NetWords = ["switch", "router", "access point", "routeros", "unifi", "edgeos", "edgeswitch", "openwrt", "dd-wrt", "pfsense", "opnsense", "mesh", "gateway", "firewall"];
    private static readonly string[] SmartMakers = ["espressif", "tuya", "shelly", "allterco", "signify", "philips lighting", "ecobee", "nest labs", "ring llc", "belkin", "lifx", "itead", "sonoff", "wiz", "govee", "ikea", "lutron", "wyze", "chamberlain", "rachio", "august", "yale", "sense labs", "tado", "netatmo", "amazon technologies", "eufy", "meross", "kasa", "wemo"];
    private static readonly string[] PhoneMakers = ["samsung", "xiaomi", "oneplus", "huawei", "honor device", "oppo", "vivo mobile", "realme", "motorola", "google", "zte", "nothing technology", "fairphone", "hmd global", "nokia", "lg electronics", "sony mobile", "tcl"];
    private static readonly string[] PcMakers = ["intel", "realtek", "dell", "lenovo", "asustek", "micro-star", "giga-byte", "gigabyte", "asrock", "hp inc", "hewlett packard", "microsoft", "liteon", "lite-on", "azurewave", "rivet networks", "killer", "hon hai", "foxconn", "quanta", "compal", "wistron", "pegatron", "acer", "toshiba", "fujitsu", "framework", "msi", "razer", "clevo", "qualcomm atheros", "mediatek", "broadcom", "aquantia", "marvell"];

    public static void Classify(Device d)
    {
        var why = new List<string>();
        var text = string.Join(" | ", d.Vendor, d.Manufacturer, d.Model, d.FriendlyName, d.SnmpDescr, d.SnmpName, d.HttpTitle, d.HttpServer, d.SsdpType, d.SsdpServer, d.MdnsName, d.DnsName, d.NetBiosName).ToLowerInvariant();
        var vendor = d.Vendor.ToLowerInvariant();
        bool Any(string[] words) => words.Any(text.Contains);
        bool Maker(string[] makers) => makers.Any(vendor.Contains);
        string First(string[] words) => words.First(text.Contains).Trim();
        var windowsPorts = d.Has(135, 139, 445, 3389, 5357);
        var apple = vendor.Contains("apple");
        var txtModel = (d.Model + " " + string.Join(" ", d.Services)).ToLowerInvariant();

        d.Os = GuessOs(d, text, windowsPorts, apple);

        (DeviceKind, string) Pick()
        {
            if (d.IsSelf)
            {
                why.Add("it's the PC running this scan");
                return (DeviceKind.ThisPc, "This PC");
            }

            // Printers say so in many ways.
            var printerHits = new List<string>();
            if (d.HasService("_ipp") || d.HasService("_printer") || d.HasService("_pdl-datastream")) printerHits.Add("it offers printing over Bonjour (" + string.Join(", ", d.Services.Where(s => s.StartsWith("_ipp") || s.StartsWith("_printer") || s.StartsWith("_pdl"))) + ")");
            if (d.Has(9100)) printerHits.Add("port 9100 (raw printing) is open");
            if (d.SsdpType.Contains("printer", StringComparison.OrdinalIgnoreCase)) printerHits.Add("it calls itself a UPnP " + d.SsdpType);
            if (Any(PrinterWords) && !d.IsGateway) printerHits.Add($"its own description says \"{First(PrinterWords)}\"");
            if (printerHits.Count == 0 && Maker(PrinterMakers) && d.Has(631, 515)) printerHits.Add($"{d.Vendor} network card with a printing port ({string.Join(", ", d.Ports.Where(p => p is 631 or 515))}) open");
            if (printerHits.Count > 0 && !(d.IsGateway && printerHits.Count < 2))
            {
                why.AddRange(printerHits);
                return (DeviceKind.Printer, d.HasService("_uscan") || d.HasService("_scanner") || text.Contains("mfp") || text.Contains("mfc-") || text.Contains("all-in-one") ? "Printer / scanner" : "Printer");
            }

            if (d.IsGateway)
            {
                why.Add("it's this network's default gateway");
                return (DeviceKind.Router, "Router (gateway)");
            }

            if (d.SsdpType.Contains("InternetGatewayDevice", StringComparison.OrdinalIgnoreCase) || d.SsdpType.Contains("WFADevice", StringComparison.OrdinalIgnoreCase))
            {
                why.Add("it announces itself as a UPnP " + d.SsdpType);
                return (DeviceKind.Router, d.SsdpType.Contains("WFA") ? "Wi-Fi access point / router" : "Router");
            }

            if (Any(ConsoleWords) || vendor.Contains("nintendo"))
            {
                why.Add($"it says \"{(Any(ConsoleWords) ? First(ConsoleWords) : "nintendo")}\"");
                return (DeviceKind.GameConsole, text.Contains("xbox") ? "Xbox" : text.Contains("playstation") || vendor.Contains("sony interactive") ? "PlayStation" : text.Contains("nintendo") ? "Nintendo console" : "Game console");
            }

            if (vendor is "virtualbox" or "qemu / kvm" or "microsoft hyper-v" or "xen" or "vmware" or "proxmox")
            {
                why.Add($"its MAC address is one {d.Vendor} gives virtual machines");
                return (DeviceKind.VirtualMachine, d.Os.Length > 0 ? $"Virtual machine ({d.Os})" : "Virtual machine");
            }

            if (Any(NasWords))
            {
                why.Add($"it says \"{First(NasWords)}\"");
                return (DeviceKind.Storage, "Network storage (NAS)");
            }

            if (Any(CameraWords) || (d.Has(554) && !windowsPorts && !d.Has(7000) && !d.HasService("_airplay")))
            {
                why.Add(Any(CameraWords) ? $"it says \"{First(CameraWords)}\"" : "port 554 (video stream, RTSP) is open");
                return (DeviceKind.Camera, text.Contains("nvr") ? "Camera recorder (NVR)" : text.Contains("doorbell") ? "Video doorbell" : "Camera");
            }

            // Apple gear on a private (random) MAC address: no maker to go on, but its services give it away.
            if (!apple && (text.Contains("macbook") || text.Contains("imac") || text.Contains("mac mini") || text.Contains("macmini")
                           || d.HasService("_rfb") && (d.HasService("_airplay") || d.HasService("_raop") || d.HasService("_companion-link"))))
            {
                why.Add(d.HasService("_rfb") ? "it offers Apple screen sharing and AirPlay" : $"its name says \"{(text.Contains("macbook") ? "macbook" : text.Contains("imac") ? "imac" : "mac mini")}\"");
                return (DeviceKind.Computer, "Mac");
            }

            if (!apple && (text.Contains("iphone") || text.Contains("ipad") || d.Has(62078) || d.HasService("_apple-mobdev2")
                           || d.HasService("_companion-link") && d.Ports.Count == 0))
            {
                why.Add(d.Has(62078) ? "port 62078 (iPhone / iPad sync) is open" : text.Contains("iphone") || text.Contains("ipad") ? $"its name says \"{(text.Contains("iphone") ? "iphone" : "ipad")}\"" : "it offers Apple's companion link with nothing open, like an iPhone");
                return (DeviceKind.Phone, text.Contains("ipad") ? "iPad" : text.Contains("iphone") ? "iPhone" : "iPhone or iPad");
            }

            // Apple: tell Macs, Apple TVs, HomePods and iPhones apart.
            if (apple)
            {
                if (txtModel.Contains("appletv"))
                {
                    why.Add("its Bonjour model is " + d.Model);
                    return (DeviceKind.Media, "Apple TV");
                }

                if (txtModel.Contains("audioaccessory") || text.Contains("homepod"))
                {
                    why.Add("its Bonjour model is " + d.Model);
                    return (DeviceKind.Media, "HomePod");
                }

                if (txtModel.Contains("mac") || text.Contains("macbook") || text.Contains("imac") || d.Has(22, 445, 548, 5900) || d.HasService("_smb") || d.HasService("_afpovertcp") || d.HasService("_workstation"))
                {
                    why.Add("Apple network card" + (d.Model.Length > 0 ? ", model " + d.Model : d.Ports.Count > 0 ? ", with " + string.Join(", ", d.Ports.Select(p => PortNames.Name(p))) + " open" : ""));
                    return (DeviceKind.Computer, "Mac");
                }

                if (txtModel.Contains("iphone") || txtModel.Contains("ipad") || d.Has(62078) || d.HasService("_apple-mobdev2"))
                {
                    why.Add(d.Has(62078) ? "port 62078 (iPhone / iPad sync) is open" : "Apple network card and it answers like a phone");
                    return (DeviceKind.Phone, txtModel.Contains("ipad") ? "iPad" : txtModel.Contains("iphone") ? "iPhone" : "iPhone or iPad");
                }

                if (d.HasService("_airplay") || d.HasService("_raop"))
                {
                    why.Add("it takes AirPlay");
                    return (DeviceKind.Media, "AirPlay device");
                }

                why.Add("Apple network card with nothing open (phones and watches look like this)");
                return (DeviceKind.Phone, "Apple device (likely iPhone or iPad)");
            }

            // TVs, speakers and streaming sticks.
            if (d.HasService("_googlecast") || d.Has(8008, 8009) && !windowsPorts)
            {
                why.Add(d.HasService("_googlecast") ? "it offers Google Cast" : "Google Cast ports (8008/8009) are open");
                var m = (d.Model + " " + d.FriendlyName).ToLowerInvariant();
                if (m.Contains("nest") || m.Contains("home mini") || m.Contains("google home") || m.Contains("audio") || m.Contains("speaker"))
                    return (DeviceKind.Media, "Smart speaker");
                return (DeviceKind.Media, m.Contains("tv") || text.Contains("tv") ? "Smart TV / Google TV" : "Chromecast / Cast device");
            }

            if (d.HasService("_sonos") || d.Has(1400) && vendor.Contains("sonos") || vendor.Contains("sonos"))
            {
                why.Add(vendor.Contains("sonos") ? "Sonos network card" : "it offers Sonos");
                return (DeviceKind.Media, "Sonos speaker");
            }

            if (vendor.Contains("roku") || d.Has(8060))
            {
                why.Add(vendor.Contains("roku") ? "Roku network card" : "port 8060 (Roku remote) is open");
                return (DeviceKind.Media, text.Contains("tv") ? "Roku TV" : "Roku");
            }

            if (d.HasService("_amzn-wplay"))
            {
                why.Add("it offers Amazon's Fire TV casting");
                return (DeviceKind.Media, "Fire TV");
            }

            if (d.HasService("_airplay") || d.HasService("_raop") || d.HasService("_spotify-connect") || d.HasService("_androidtvremote2")
                || d.SsdpType.Contains("MediaRenderer", StringComparison.OrdinalIgnoreCase) || Any(TvWords) && !windowsPorts)
            {
                why.Add(d.SsdpType.Contains("MediaRenderer", StringComparison.OrdinalIgnoreCase) ? "it's a UPnP media player (MediaRenderer)"
                    : d.HasService("_airplay") || d.HasService("_raop") ? "it takes AirPlay"
                    : d.HasService("_spotify-connect") ? "it offers Spotify Connect"
                    : d.HasService("_androidtvremote2") ? "it offers the Android TV remote"
                    : $"it says \"{First(TvWords)}\"");
                return (DeviceKind.Media, text.Contains("tv") || d.HasService("_androidtvremote2") ? "Smart TV" : "Media player / speaker");
            }

            if (d.Has(8006))
            {
                why.Add("port 8006 (Proxmox) is open");
                return (DeviceKind.Server, "Proxmox server");
            }

            // Network gear: switches, access points, mesh nodes.
            var snmpNet = (d.SnmpDescr + " " + d.HttpTitle).ToLowerInvariant();
            if (NetWords.Any(snmpNet.Contains) || Maker(NetMakers) && !windowsPorts || Maker(NetMakers) && d.SnmpDescr.Length > 0)
            {
                if (vendor.Contains("tp-link") && !d.Has(80, 443) && d.SnmpDescr.Length == 0)
                {
                    why.Add("TP-Link network card with no web page (their smart plugs and bulbs look like this)");
                    return (DeviceKind.SmartHome, "Smart plug / bulb");
                }

                why.Add(NetWords.Any(snmpNet.Contains) ? $"its own description says \"{NetWords.First(snmpNet.Contains)}\"" : $"{d.Vendor} makes network gear");
                return (DeviceKind.NetworkGear, vendor.Contains("quectel") || vendor.Contains("sierra") || vendor.Contains("telit") || vendor.Contains("inseego") || vendor.Contains("franklin") ? "Cellular modem / router" : snmpNet.Contains("switch") ? "Network switch" : snmpNet.Contains("access point") || text.Contains("unifi") || text.Contains("eero") || snmpNet.Contains("mesh") ? "Wi-Fi access point" : "Network device");
            }

            // Smart home.
            if (d.HasService("_hap") || d.HasService("_homekit") || d.HasService("_matter") || d.HasService("_hue") || d.HasService("_esphomelib") || d.HasService("_home-assistant")
                || d.Has(8123) || Maker(SmartMakers) || d.Has(1883) && !windowsPorts)
            {
                if (d.Has(8123) || d.HasService("_home-assistant"))
                {
                    why.Add("Home Assistant answers on it");
                    return (DeviceKind.SmartHome, "Home Assistant hub");
                }

                if (vendor.Contains("amazon"))
                {
                    why.Add("Amazon network card with no web page (Echo speakers and Fire tablets look like this)");
                    return (DeviceKind.SmartHome, "Amazon device (Echo / Fire)");
                }

                why.Add(Maker(SmartMakers) ? $"{d.Vendor} makes smart-home gear" : d.Has(1883) ? "port 1883 (MQTT) is open" : "it offers " + string.Join(", ", d.Services.Where(s => s is "_hap._tcp" or "_homekit._tcp" or "_matter._tcp" or "_hue._tcp" or "_esphomelib._tcp")));
                return (DeviceKind.SmartHome, d.HasService("_hue") || vendor.Contains("signify") || vendor.Contains("philips lighting") ? "Philips Hue bridge" : "Smart home device");
            }

            if (d.Has(32400))
            {
                why.Add("port 32400 (Plex) is open");
                return (DeviceKind.Server, "Plex media server");
            }

            if (vendor.Contains("raspberry"))
            {
                why.Add("Raspberry Pi network card");
                return (DeviceKind.Computer, "Raspberry Pi");
            }

            // Computers.
            if (windowsPorts || d.NetBiosName.Length > 0 || d.HasService("_workstation") || d.HasService("_rdlink"))
            {
                var bits = new List<string>();
                if (d.Has(445)) bits.Add("file sharing");
                if (d.Has(3389)) bits.Add("Remote Desktop");
                if (d.Has(135)) bits.Add("Windows RPC");
                if (d.NetBiosName.Length > 0) bits.Add("a NetBIOS name");
                why.Add("it answers with " + (bits.Count > 0 ? string.Join(", ", bits) : "Windows ports open"));
                var server = text.Contains("server") || d.Has(53) && d.Has(445);
                return d.Os == "Windows" ? (server ? DeviceKind.Server : DeviceKind.Computer, server ? "Windows server" : "Windows PC") : (DeviceKind.Computer, d.Os.Length > 0 ? d.Os + " computer" : "Computer");
            }

            if (d.Has(22) || d.Os == "Linux")
            {
                why.Add(d.Has(22) ? "SSH (port 22) is open" : "it answers like Linux");
                return (DeviceKind.Server, d.Os.Length > 0 ? d.Os + " computer / server" : "Server");
            }

            if (Maker(PcMakers) && !d.RandomMac)
            {
                why.Add($"{d.Vendor} network card (PCs and laptops)");
                return (DeviceKind.Computer, d.Vendor.Contains("Microsoft") ? "Microsoft device (Surface / Xbox)" : "Computer");
            }

            if (Maker(PhoneMakers) && d.Ports.Count == 0)
            {
                why.Add($"{d.Vendor} network card with nothing open (phones and tablets look like this)");
                return (DeviceKind.Phone, d.Os == "Android" ? "Android phone or tablet" : "Phone or tablet");
            }

            if (d.RandomMac && d.Ports.Count == 0)
            {
                why.Add("a private (random) MAC address and nothing open: phones, tablets and some laptops do this on Wi-Fi");
                return (DeviceKind.Phone, "Phone or tablet (private MAC)");
            }

            if (d.Has(80, 443, 8080, 8443))
            {
                why.Add("it only has a web page" + (d.HttpTitle.Length > 0 ? $" (\"{d.HttpTitle}\")" : ""));
                return (DeviceKind.Unknown, "Device with a web page");
            }

            why.Add(d.Vendor.Length > 0 ? $"made by {d.Vendor}, but nothing it answered says what it is" : "nothing it answered says what it is");
            return (DeviceKind.Unknown, "Unknown device");
        }

        var (kind, kindText) = Pick();
        d.Kind = kind;
        d.KindText = kindText;
        d.Why = why;
    }

    private static string GuessOs(Device d, string text, bool windowsPorts, bool apple)
    {
        if (d.IsSelf || windowsPorts && d.Ttl is 0 or > 64 and <= 128 || d.NetBiosName.Length > 0 && d.Ttl is > 64 and <= 128) return "Windows";
        if (text.Contains("windows")) return "Windows";
        if (apple) return text.Contains("iphone") || text.Contains("ipad") || d.Has(62078) ? "iOS" : d.Model.Contains("Mac", StringComparison.OrdinalIgnoreCase) || d.Has(22, 548, 5900) ? "macOS" : "";
        if (text.Contains("android")) return "Android";
        if (text.Contains("ubuntu") || text.Contains("debian") || text.Contains("raspbian") || text.Contains("fedora") || text.Contains("linux") || text.Contains("proxmox") || d.Has(8006)) return "Linux";
        if (d.Has(22) && d.Ttl is > 0 and <= 64) return "Linux";
        return "";
    }

    /// <summary>The sidebar's groups.</summary>
    public static readonly (string Name, string Glyph, DeviceKind[] Kinds)[] Groups =
    [
        ("All devices", "", []),
        ("Computers & servers", "", [DeviceKind.ThisPc, DeviceKind.Computer, DeviceKind.Server, DeviceKind.VirtualMachine, DeviceKind.Storage]),
        ("Printers", "", [DeviceKind.Printer]),
        ("Phones & tablets", "", [DeviceKind.Phone]),
        ("TVs & media", "", [DeviceKind.Media, DeviceKind.GameConsole]),
        ("Network gear", "", [DeviceKind.Router, DeviceKind.NetworkGear]),
        ("Smart home & cameras", "", [DeviceKind.SmartHome, DeviceKind.Camera]),
        ("Unknown", "", [DeviceKind.Unknown]),
    ];

    public static string Glyph(DeviceKind k) => k switch
    {
        DeviceKind.ThisPc => "",
        DeviceKind.Computer => "",
        DeviceKind.Server => "",
        DeviceKind.VirtualMachine => "",
        DeviceKind.Storage => "",
        DeviceKind.Printer => "",
        DeviceKind.Phone => "",
        DeviceKind.Media => "",
        DeviceKind.GameConsole => "",
        DeviceKind.Camera => "",
        DeviceKind.SmartHome => "",
        DeviceKind.NetworkGear => "",
        DeviceKind.Router => "",
        _ => "",
    };
}
