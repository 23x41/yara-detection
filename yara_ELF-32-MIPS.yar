rule ELF_32_MIPS_IoT_Botnet
{
    meta:
        description = "Detects 32-bit MIPS ELF IoT botnets (Gafgyt, Mirai, Tsunami and variants)"
        author = "Grok"
        date = "2026-07-30"
        arch = "MIPS 32-bit"
        reference = "Bazaar.2026.06 ELF_32_MIPS set"

    strings:
        // Common Gafgyt / Bashlite strings
        $gaf1 = "gayfgt" ascii
        $gaf2 = "/bin/busybox" ascii
        $gaf3 = "/proc/net/route" ascii
        $gaf4 = "PONG!" ascii
        $gaf5 = "GETLOCALIP" ascii
        $gaf6 = "HTTPFLOOD" ascii
        $gaf7 = "UDP" ascii
        $gaf8 = "SYN" ascii
        $gaf9 = "TELNET LOGIN CRACKED" ascii
        $gaf10 = "busyboxterrorist" ascii

        // Common Mirai-style strings
        $mir1 = "/dev/watchdog" ascii
        $mir2 = "/dev/misc/watchdog" ascii
        $mir3 = "POST /cdn-cgi/" ascii
        $mir4 = "REPORT %s:%s" ascii

        // Generic IoT bot / scanner strings
        $bot1 = "BOGOMIPS" ascii
        $bot2 = "processor" ascii
        $bot3 = "root" ascii
        $bot4 = "admin" ascii
        $bot5 = "support" ascii
        $bot6 = "user" ascii
        $bot7 = "login" ascii
        $bot8 = "pass" ascii
        $bot9 = "shell" ascii
        $bot10 = "enable" ascii

    condition:
        // Must be 32-bit ELF
        uint32(0) == 0x464C457F and
        uint8(4) == 1 and                    // 32-bit
        (
            // MIPS architecture (EM_MIPS = 8)
            uint16(18) == 0x0008 or          // little endian
            uint16(18) == 0x0800             // big endian
        ) and
        filesize < 500KB and
        (
            // Strong Gafgyt indicators
            3 of ($gaf*) or
            // Mirai-style
            2 of ($mir*) or
            // Generic bot + at least one strong string
            (4 of ($bot*) and 1 of ($gaf*)) or
            // Multiple bot strings
            5 of ($bot*)
        )
}
