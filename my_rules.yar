/* Rule to identify file types */
rule Identify_PE_File {
    condition:
        uint16(0) == 0x5A4D  // "MZ" header for Windows Executables
}

rule Identify_PDF {
    condition:
        uint32(0) == 0x46445025 // "%PDF" header
}

/* Rule to detect suspicious malware behavior */
rule Suspicious_Strings {
    meta:
        description = "Detects common malware API calls"
    strings:
        $s1 = "CreateRemoteThread" ascii nocase
        $s2 = "ShellExecute" ascii nocase
        $s3 = "GetProcAddress" ascii nocase
    condition:
        any of them
}