import "pe"
import "math"

rule Suspicious_PE_Loader_Traits
{
    meta:
        description = "Detects PE files with multiple suspicious loader/dropper characteristics commonly seen in in-the-wild malware"
        author = "YourGitHubUsername"
        date = "2026-07-30"
        reference = "Portfolio detection engineering work"
        score = 70
        tags = "loader, dropper, pe, hunting"

    strings:
        $s1 = "VirtualAlloc" ascii wide
        $s2 = "VirtualProtect" ascii wide
        $s3 = "WriteProcessMemory" ascii wide
        $s4 = "CreateRemoteThread" ascii wide
        $s5 = "NtUnmapViewOfSection" ascii wide
        $s6 = "RtlDecompressBuffer" ascii wide
        $s7 = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 E8 }   // common push-push-call pattern

    condition:
        // Check for MZ header (works on all YARA versions)
        uint16(0) == 0x5A4D and

        // File size sanity
        filesize > 20KB and filesize < 15MB and

        // High entropy in at least one executable section
        for any i in (0..pe.number_of_sections - 1) : (
            (pe.sections[i].characteristics & pe.SECTION_CNT_CODE) and
            math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 7.0
        ) and

        // At least 3 of the suspicious strings
        3 of ($s*)
}
