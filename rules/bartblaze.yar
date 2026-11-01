/*
==============================================================================
MalShot YARA Integration
Resource Name: BartBlaze YARA Rules
Purpose / Target: Endpoint Security
Direct Link: https://github.com/BartBlaze/Yara-rules
Description: Focused on desktop malware, infostealers, RATs, and ransomware strains.
License / Attribution: CC-BY-4.0 / BartBlaze
Hermes Grounded Provenance: Verified from upstream raw repositories
==============================================================================
*/


// --- Upstream Source: https://raw.githubusercontent.com/BartBlaze/Yara-rules/master/rules/APT/Autumn_Backdoor.yar ---
rule Autumn_Backdoor
{
    meta:
        id = "2kQ17alOYwTwkkTNA8vZCX"
        fingerprint = "v1_sha256_7a32b90fb6e962a82af808d698dc19d503c075606f5a7e52f783f0c7d71f5936"
        version = "2.0"
        date = "2025-09-26"
        modified = "2025-11-18"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies backdoored libcef.dll (stage 1), used by a China-nexus APT, as seen in the Autumn Dragon report."
        category = "MALWARE"
        malware = "UNKNOWN"
        malware_type = "BACKDOOR"
        reference = "https://cyberarmor.tech/blog/autumn-dragon-china-nexus-apt-group-targets-south-east-asia"
        hash = "a3805b24b66646c0cf7ca9abad502fe15b33b53e56a04489cfb64a238616a7bf"

    strings:
        $s1 = "Could not get process list."
        $s2 = "Please send the document now." 
        $s3 = "Failed to create pipe." 
        $s4 = "Failed to start process." 
        $s5 = "Command executed but returned no output." 
		$s6 = "Screenshot taken."
		$s7 = "Please send a document, not text."

        $x1 = "No file or photo found in message."
        $x2 = "Error: Cannot create file on disk."
        $x3 = "File saved to: "
        $x4 = "Error receiving file:"
		
    condition:
        4 of ($s*) or 3 of ($x*)
}


// --- Upstream Source: https://raw.githubusercontent.com/BartBlaze/Yara-rules/master/rules/ransomware/Maze.yar ---
rule Maze
{
    meta:
        id = "4sTbmIEE40nSKc9rOEz4po"
        fingerprint = "305df5e5f0a4d5660dff22073881e65ff25528895abf26308ecd06dd70a97ec2"
        version = "1.0"
        creation_date = "2019-11-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Maze ransomware in memory or unpacked."
        category = "MALWARE"
        malware = "MAZE"
        malware_type = "RANSOMWARE"
        mitre_att = "S0449"

    strings:
        $ = "Enc: %s" ascii wide
        $ = "Encrypting whole system" ascii wide
        $ = "Encrypting specified folder in --path parameter..." ascii wide
        $ = "!Finished in %d ms!" ascii wide
        $ = "--logging" ascii wide
        $ = "--nomutex" ascii wide
        $ = "--noshares" ascii wide
        $ = "--path" ascii wide
        $ = "Logging enabled | Maze" ascii wide
        $ = "NO SHARES | " ascii wide
        $ = "NO MUTEX | " ascii wide
        $ = "Encrypting:" ascii wide
        $ = "You need to buy decryptor in order to restore the files." ascii wide
        $ = "Dear %s, your files have been encrypted by RSA-2048 and ChaCha algorithms" ascii wide
        $ = "%s! Alert! %s! Alert! Dear %s Your files have been encrypted by %s! Attention! %s" ascii wide
        $ = "DECRYPT-FILES.txt" ascii wide fullword

    condition:
        5 of them
}

// --- Upstream Source: https://raw.githubusercontent.com/BartBlaze/Yara-rules/master/rules/ransomware/Darkside.yar ---
rule Darkside
{
    meta:
        id = "5qjcs58k9iHd3EU3xv66sV"
        fingerprint = "57bc5c7353c8c518e057456b2317e1dbf59ee17ce69cd336f1bacaf627e9efd5"
        version = "1.0"
        creation_date = "2021-05-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Darkside ransomware."
        category = "MALWARE"
        malware = "DARKSIDE"
        malware_type = "RANSOMWARE"

    strings:
        $ = "darkside_readme.txt" ascii wide
        $ = "[ Welcome to DarkSide ]" ascii wide
        $ = { 66 c7 04 47 2a 00 c7 44 47 02 72 00 65 00 c7 44 47 06 63 00 79 00 c7 44 47 0a 63 00 6c 00 c7 44 47 0e 65 00 2a 00 66 c7 44 47 12 00 00 }
        $ = { c7 00 2a 00 72 00 c7 40 04 65 00 63 00 c7 40 08 79 00 63 00 c7 40 0c 6c 00 65 00 c7 40 10 2a 00 00 00 }

    condition:
        any of them
}