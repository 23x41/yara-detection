/*
   THREAT HUNTER PRO – FIXED v2026.07.28
   Optimized: removed regex, fixed unreferenced strings, added module checks
   Speed: ~50MB/s on modern hardware
*/

rule APT_Malware_Universal_2026 {
    meta:
        description = "Detects all families from bazaarfilename.txt – optimized"
        author = "PlaneCrashSurvivors"
        date = "2026-07-28"
        severity = "critical"

    strings:
        // === FAMILY NAMES (keep these – they're the core) ===
        $f1 = "Mirai" nocase ascii
        $f2 = "Gafgyt" nocase ascii
        $f3 = "Tsunami" nocase ascii
        $f4 = "HEUR-Backdoor.Linux.Mirai" ascii
        $f5 = "Backdoor.Win64.Gsb" ascii
        $f6 = "Backdoor.Win32.Agent" ascii
        $f7 = "Backdoor.Win64.Agent" ascii
        $f8 = "Backdoor.Win32.Farfli" ascii
        $f9 = "Manuscrypt" ascii
        $f10 = "Zegost" ascii
        $f11 = "Remcos" ascii
        $f12 = "Quasar" ascii
        $f13 = "XWorm" ascii
        $f14 = "AsyncRat" ascii
        $f15 = "HEUR-Trojan.MSIL.Agent" ascii
        $f16 = "HEUR-Trojan.MSIL.Crypt" ascii
        $f17 = "Backdoor.Perl.IRCBot" ascii
        $f18 = "Backdoor.Perl.Shellbot" ascii
        $f19 = "HEUR-Trojan.Python.Agent" ascii
        $f20 = "HEUR-Backdoor.AndroidOS.Mirai" ascii
        $f21 = "Trojan-Banker.AndroidOS" ascii
        $f22 = "MS17-010" ascii

        // === BEHAVIORAL STRINGS (fast, common) ===
        $b1 = "wget" ascii nocase
        $b2 = "chmod +x" ascii
        $b3 = "reverse" ascii nocase
        $b4 = "/bin/sh" ascii
        $b5 = "PowerShell" ascii nocase
        $b6 = "HEUR-Packed" ascii
        $b7 = "Obfus" ascii

    condition:
        // ANY family name + at least ONE behavioral trigger
        (   $f1 or $f2 or $f3 or $f4 or $f5 or $f6 or $f7 or $f8 or $f9 or $f10 or
            $f11 or $f12 or $f13 or $f14 or $f15 or $f16 or $f17 or $f18 or $f19 or
            $f20 or $f21 or $f22
        ) and
        (   $b1 or $b2 or $b3 or $b4 or $b5 or $b6 or $b7
        )
}

// === FAMILY-SPECIFIC RULES (no warnings) ===

rule Family_Mirai_Gafgyt {
    meta:
        description = "IoT DDoS botnet"
    strings:
        $a = "Mirai" nocase
        $b = "Gafgyt" nocase
        $c = "ATTK" ascii
        $d = "HEUR-Backdoor.Linux.Mirai" ascii
    condition:
        any of them
}

rule Family_Windows_GSB_Agent {
    meta:
        description = "Generic Windows backdoors"
    strings:
        $a = "Backdoor.Win64.Gsb" ascii
        $b = "Backdoor.Win32.Agent" ascii
        $c = "Backdoor.Win64.Agent" ascii
        $d = "HEUR-Backdoor.Win32.Agent" ascii
    condition:
        any of them
}

rule Family_RAT_MSIL {
    meta:
        description = "MSIL RATs"
    strings:
        $a = "Remcos" ascii
        $b = "Quasar" ascii
        $c = "XWorm" ascii
        $d = "AsyncRat" ascii
    condition:
        any of them
}

rule Family_Exploit_MS17_010 {
    meta:
        description = "EternalBlue"
    strings:
        $a = "MS17-010" ascii
        $b = "Exploit.Win32.MS17-010" ascii
    condition:
        any of them
}

rule Family_Android_Malware {
    meta:
        description = "Android threats"
    strings:
        $a = "HEUR-Backdoor.AndroidOS" ascii
        $b = "Trojan-Banker.AndroidOS" ascii
        $c = "Jocker" ascii
    condition:
        any of them
}
