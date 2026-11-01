/*
==============================================================================
MalShot YARA Integration
Resource Name: AlienVault OTX Rules
Purpose / Target: Threat Intelligence
Direct Link: https://github.com/AlienVault-OTX/YARA
Description: Community-contributed rules from AT&T AlienVault Open Threat Exchange & AlienVault Labs.
License / Attribution: Apache 2.0 / AlienVault
Hermes Grounded Provenance: Verified from upstream raw repositories
==============================================================================
*/


// --- Upstream Source: https://raw.githubusercontent.com/AlienVault-Labs/AlienVaultLabs/master/malware_rulesets/yara/vmdetect.yar ---

rule vmdetect_misc : vmdetect
{
	meta:
		author = "AlienVault Labs"
		type = "info"
		severity = 1
		description = "Virtual Machine detection tricks"

	strings:
		$vbox1 = "VBoxService" nocase ascii wide
		$vbox2 = "VBoxTray" nocase ascii wide
		$vbox3 = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" nocase ascii wide
		$vbox4 = "SOFTWARE\\\\Oracle\\\\VirtualBox Guest Additions" nocase ascii wide

		$wine1 = "wine_get_unix_file_name" ascii wide

		$vmware1 = "vmmouse.sys" ascii wide
		$vmware2 = "VMware Virtual IDE Hard Drive" ascii wide

		$miscvm1 = "SYSTEM\\ControlSet001\\Services\\Disk\\Enum" nocase ascii wide
		$miscvm2 = "SYSTEM\\\\ControlSet001\\\\Services\\\\Disk\\\\Enum" nocase ascii wide

		// Drivers
		$vmdrv1 = "hgfs.sys" ascii wide
		$vmdrv2 = "vmhgfs.sys" ascii wide
		$vmdrv3 = "prleth.sys" ascii wide
		$vmdrv4 = "prlfs.sys" ascii wide
		$vmdrv5 = "prlmouse.sys" ascii wide
		$vmdrv6 = "prlvideo.sys" ascii wide
		$vmdrv7 = "prl_pv32.sys" ascii wide
		$vmdrv8 = "vpc-s3.sys" ascii wide
		$vmdrv9 = "vmsrvc.sys" ascii wide
		$vmdrv10 = "vmx86.sys" ascii wide
		$vmdrv11 = "vmnet.sys" ascii wide

		// SYSTEM\ControlSet001\Services
		$vmsrvc1 = "vmicheartbeat" ascii wide
		$vmsrvc2 = "vmicvss" ascii wide
		$vmsrvc3 = "vmicshutdown" ascii wide
		$vmsrvc4 = "vmicexchange" ascii wide
		$vmsrvc5 = "vmci" ascii wide
		$vmsrvc6 = "vmdebug" ascii wide
		$vmsrvc7 = "vmmouse" ascii wide
		$vmsrvc8 = "VMTools" ascii wide
		$vmsrvc9 = "VMMEMCTL" ascii wide
		$vmsrvc10 = "vmware" ascii wide
		$vmsrvc11 = "vmx86" ascii wide
		$vmsrvc12 = "vpcbus" ascii wide
		$vmsrvc13 = "vpc-s3" ascii wide
		$vmsrvc14 = "vpcuhub" ascii wide
		$vmsrvc15 = "msvmmouf" ascii wide
		$vmsrvc16 = "VBoxMouse" ascii wide
		$vmsrvc17 = "VBoxGuest" ascii wide
		$vmsrvc18 = "VBoxSF" ascii wide
		$vmsrvc19 = "xenevtchn" ascii wide
		$vmsrvc20 = "xennet" ascii wide
		$vmsrvc21 = "xennet6" ascii wide
		$vmsrvc22 = "xensvc" ascii wide
		$vmsrvc23 = "xenvdb" ascii wide

		// Processes
		$miscproc1 = "vmware2" ascii wide
		$miscproc2 = "vmount2" ascii wide
		$miscproc3 = "vmusrvc" ascii wide
		$miscproc4 = "vmsrvc" ascii wide
		$miscproc5 = "vboxservice" ascii wide
		$miscproc6 = "vboxtray" ascii wide
		$miscproc7 = "xenservice" ascii wide

		$vmware_mac_1a = "00-05-69"
		$vmware_mac_1b = "00:05:69"
		$vmware_mac_2a = "00-50-56"
		$vmware_mac_2b = "00:50:56"
		$vmware_mac_3a = "00-0C-29"
		$vmware_mac_3b = "00:0C:29"
		$vmware_mac_4a = "00-1C-14"
		$vmware_mac_4b = "00:1C:14"
		$virtualbox_mac_1a = "08-00-27"
		$virtualbox_mac_1b = "08:00:27"

	condition:
		2 of them
}



// --- Upstream Source: https://raw.githubusercontent.com/AlienVault-Labs/AlienVaultLabs/master/malware_rulesets/yara/sandboxdetect.yar ---

rule sandboxdetect_misc : sandboxdetect
{
	meta:
		author = "AlienVault Labs"
		type = "info"
		severity = 1
		description = "Sandbox detection tricks"

	strings:
		$sbxie1 = "sbiedll" nocase ascii wide

		// CWSandbox
		$prodid1 = "55274-640-2673064-23950" ascii wide
		$prodid2 = "76487-644-3177037-23510" ascii wide
		$prodid3 = "76487-337-8429955-22614" ascii wide

		$proc1 = "joeboxserver" ascii wide
		$proc2 = "joeboxcontrol" ascii wide
	condition:
		any of them
}



// --- Upstream Source: https://raw.githubusercontent.com/AlienVault-Labs/AlienVaultLabs/master/malware_rulesets/yara/dbgdetect.yar ---

rule dbgdetect_funcs : dbgdetect
{
	meta:
		author = "AlienVault Labs"
		type = "info"
		severity = 1
		description = "Debugger detection tricks"

	strings:
		$func1 = "IsDebuggerPresent"
		$func2 = "OutputDebugString"
		$func3 = "ZwQuerySystemInformation"
		$func4 = "ZwQueryInformationProcess"
		$func5 = "IsDebugged"
		$func6 = "NtGlobalFlags"
		$func7 = "CheckRemoteDebuggerPresent"
		$func8 = "SetInformationThread"
		$func9 = "DebugActiveProcess"

	condition:
		2 of them
}

rule dbgdetect_procs : dbgdetect
{
	meta:
		author = "AlienVault Labs"
		type = "info"
		severity = 1
		description = "Debugger detection tricks"

	strings:
		$proc1 = "wireshark" nocase ascii wide
		$proc2 = "filemon" nocase ascii wide
		$proc3 = "procexp" nocase ascii wide
		$proc4 = "procmon" nocase ascii wide
		$proc5 = "regmon" nocase ascii wide
		$proc6 = "idag" nocase ascii wide
		$proc7 = "immunitydebugger" nocase ascii wide
		$proc8 = "ollydbg" nocase ascii wide
		$proc9 = "petools" nocase ascii wide

	condition:
		2 of them
}

rule dbgdetect_files : dbgdetect
{
	meta:
		author = "AlienVault Labs"
		type = "info"
		severity = 1
		description = "Debugger detection tricks"
	strings:
		$file1 = "syserdbgmsg" nocase ascii wide
		$file2 = "syserboot" nocase ascii wide
		$file3 = "SICE" nocase ascii wide
		$file4 = "NTICE" nocase ascii wide
	condition:
		2 of them
}



// --- Upstream Source: https://raw.githubusercontent.com/AlienVault-OTX/YARA/master/sample.rules ---

rule UPX : Packer
{
    strings: 
        $a = {60 E8 00 00 00 00 58 83 E8 3D 50 8D B8}

    condition:
        $a at entrypoint
        
}

