import os
import shutil
import urllib.request
from pathlib import Path
import yara

headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

def fetch_raw(url):
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.read().decode("utf-8", errors="replace")

rules_dir = Path("rules")
rules_dir.mkdir(exist_ok=True)

manifest_info = [
    {
        "filename": "yara_rules_official.yar",
        "resource_name": "YARA-Rules Official",
        "purpose": "Rule Collection",
        "direct_link": "https://github.com/YARA-Rules/rules",
        "description": "Community repository covering malware families, packers, webshells, and mobile threats.",
        "license": "GNU GPL v2",
        "sources": [
            "https://raw.githubusercontent.com/YARA-Rules/rules/master/antidebug_antivm/antidebug_antivm.yar",
            "https://raw.githubusercontent.com/YARA-Rules/rules/master/capabilities/capabilities.yar",
            "https://raw.githubusercontent.com/YARA-Rules/rules/master/cve_rules/CVE-2018-20250.yar",
        ]
    },
    {
        "filename": "signature_base.yar",
        "resource_name": "Florian Roth (Signature-Base)",
        "purpose": "Heuristics & APTs",
        "direct_link": "https://github.com/Neo23x0/signature-base",
        "description": "Industry-standard rules for ransomware, APT tools, obfuscation, and PE header anomalies.",
        "license": "Detection Rule License (DRL) 1.1 / Florian Roth",
        "sources": [
            "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_agent_btz.yar",
            "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_alienspy_rat.yar",
            "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/apt_apt10.yar",
        ]
    },
    {
        "filename": "reversinglabs.yar",
        "resource_name": "ReversingLabs Rules",
        "purpose": "Threat Detection",
        "direct_link": "https://github.com/reversinglabs/reversinglabs-yara-rules",
        "description": "High-confidence production rules maintained by ReversingLabs research team.",
        "license": "Apache 2.0 / ReversingLabs",
        "sources": [
            "https://raw.githubusercontent.com/reversinglabs/reversinglabs-yara-rules/develop/yara/backdoor/ByteCode.MSIL.Backdoor.AsyncRAT.yara",
            "https://raw.githubusercontent.com/reversinglabs/reversinglabs-yara-rules/develop/yara/backdoor/ByteCode.MSIL.Backdoor.AgentRacoon.yara",
            "https://raw.githubusercontent.com/reversinglabs/reversinglabs-yara-rules/develop/yara/backdoor/ByteCode.MSIL.Backdoor.LimeRAT.yara",
        ]
    },
    {
        "filename": "bartblaze.yar",
        "resource_name": "BartBlaze YARA Rules",
        "purpose": "Endpoint Security",
        "direct_link": "https://github.com/BartBlaze/Yara-rules",
        "description": "Focused on desktop malware, infostealers, RATs, and ransomware strains.",
        "license": "CC-BY-4.0 / BartBlaze",
        "sources": [
            "https://raw.githubusercontent.com/BartBlaze/Yara-rules/master/rules/APT/Autumn_Backdoor.yar",
            "https://raw.githubusercontent.com/BartBlaze/Yara-rules/master/rules/ransomware/Maze.yar",
            "https://raw.githubusercontent.com/BartBlaze/Yara-rules/master/rules/ransomware/Darkside.yar",
        ]
    },
    {
        "filename": "elastic_security.yar",
        "resource_name": "Elastic Security Rules",
        "purpose": "Endpoint Detection",
        "direct_link": "https://github.com/elastic/yara-rules",
        "description": "Production-grade detection rules maintained by Elastic Endpoint Security (protections-artifacts).",
        "license": "Elastic License v2 / Elastic",
        "sources": [
            "https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Windows_Backdoor_DragonCastling.yar",
            "https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Windows_Backdoor_Goldbackdoor.yar",
            "https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Windows_Trojan_CobaltStrike.yar",
        ]
    },
    {
        "filename": "inquest_awesome.yar",
        "resource_name": "InQuest Awesome-YARA",
        "purpose": "Aggregated Rules",
        "direct_link": "https://github.com/InQuest/awesome-yara",
        "description": "Directory linking to hundreds of categorized open-source YARA repositories & InQuest threat intelligence.",
        "license": "CC0-1.0 / MIT / InQuest",
        "sources": [
            "https://raw.githubusercontent.com/InQuest/yara-rules-vt/main/Apt29_DLL_May2022.yar",
            "https://raw.githubusercontent.com/InQuest/yara-rules-vt/main/Base64_Encoded_Powershell_Directives.yar",
            "https://raw.githubusercontent.com/InQuest/yara-rules-vt/main/Controlword_Whitespace_RTF.yar",
        ]
    },
    {
        "filename": "alienvault_otx.yar",
        "resource_name": "AlienVault OTX Rules",
        "purpose": "Threat Intelligence",
        "direct_link": "https://github.com/AlienVault-OTX/YARA",
        "description": "Community-contributed rules from AT&T AlienVault Open Threat Exchange & AlienVault Labs.",
        "license": "Apache 2.0 / AlienVault",
        "sources": [
            "https://raw.githubusercontent.com/AlienVault-Labs/AlienVaultLabs/master/malware_rulesets/yara/vmdetect.yar",
            "https://raw.githubusercontent.com/AlienVault-Labs/AlienVaultLabs/master/malware_rulesets/yara/sandboxdetect.yar",
            "https://raw.githubusercontent.com/AlienVault-Labs/AlienVaultLabs/master/malware_rulesets/yara/dbgdetect.yar",
            "https://raw.githubusercontent.com/AlienVault-OTX/YARA/master/sample.rules",
        ]
    },
    {
        "filename": "cape_sandbox.yar",
        "resource_name": "CAPE Sandbox Signatures",
        "purpose": "Behavioral Rules",
        "direct_link": "https://github.com/kevoreilly/CAPEv2/tree/master/analyzer/windows/modules/signatures",
        "description": "Execution rules and behavior patterns from automated sandbox analysis.",
        "license": "GPLv3 / Kevin O'Reilly & CAPE Sandbox Community",
        "sources": [
            "https://raw.githubusercontent.com/kevoreilly/CAPEv2/master/analyzer/windows/data/yara/AgentTesla.yar",
            "https://raw.githubusercontent.com/kevoreilly/CAPEv2/master/analyzer/windows/data/yara/Amatera.yar",
            "https://raw.githubusercontent.com/kevoreilly/CAPEv2/master/analyzer/windows/data/yara/DarkGate.yar",
            "https://raw.githubusercontent.com/kevoreilly/CAPEv2/master/analyzer/windows/data/yara/Formbook.yar",
        ]
    },
]

print("Fetching and assembling YARA rules into ./rules/ ...")
for item in manifest_info:
    dest_path = rules_dir / item["filename"]
    print(f"\nProcessing {item['resource_name']} -> {dest_path}")
    
    parts = []
    header = f"""/*
==============================================================================
MalShot YARA Integration
Resource Name: {item['resource_name']}
Purpose / Target: {item['purpose']}
Direct Link: {item['direct_link']}
Description: {item['description']}
License / Attribution: {item['license']}
Hermes Grounded Provenance: Verified from upstream raw repositories
==============================================================================
*/\n"""
    parts.append(header)
    
    for u in item["sources"]:
        print(f"  Fetching {u} ...")
        raw = fetch_raw(u)
        parts.append(f"// --- Upstream Source: {u} ---\n" + raw)
        
    full_content = "\n\n".join(parts)
    
    # Validate compilation
    try:
        yara.compile(source=full_content)
        dest_path.write_text(full_content, encoding="utf-8")
        print(f"  [OK] Saved {dest_path} ({len(full_content.splitlines())} lines) - compiles cleanly!")
    except Exception as e:
        print(f"  [ERROR] Compilation failed for {dest_path}: {e}")
        raise

print("\n--- Validating all files in ./rules/ together ---")
all_files = {p.stem: str(p) for p in rules_dir.glob("*.yar*")}
compiler = yara.compile(filepaths=all_files)
print(f"SUCCESS: All {len(all_files)} files in ./rules/ compiled together with ZERO errors!")
