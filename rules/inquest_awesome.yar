/*
==============================================================================
MalShot YARA Integration
Resource Name: InQuest Awesome-YARA
Purpose / Target: Aggregated Rules
Direct Link: https://github.com/InQuest/awesome-yara
Description: Directory linking to hundreds of categorized open-source YARA repositories & InQuest threat intelligence.
License / Attribution: CC0-1.0 / MIT / InQuest
Hermes Grounded Provenance: Verified from upstream raw repositories
==============================================================================
*/


// --- Upstream Source: https://raw.githubusercontent.com/InQuest/yara-rules-vt/main/Apt29_DLL_May2022.yar ---
import "pe"

rule apt29_dll_may2022 :  SVR G0016 apt29 NOBELIUM UNC2452 Russia
{
	meta:
        author           = "InQuest Labs"
        description      = "This signature detects .DLL files associated with recent APT29 (Russia, NOBELIUM) activity"
        created_date     = "2022-05-09"
        updated_date     = "2022-05-09"
        sample1          = "6fc54151607a82d5f4fae661ef0b7b0767d325f5935ed6139f8932bc27309202"
        sample2          = "6618a8b55181b1309dc897d57f9c7264e0c07398615a46c2d901dd1aa6b9a6d6"
        sample3          = "6618a8b55181b1309dc897d57f9c7264e0c07398615a46c2d901dd1aa6b9a6d6"
        imphash          = "b4a3f218dbd33872d0fd88a2ff95be76"         
        sample_reference = "https://www.joesandbox.com/analysis/621068/0/html"
        mitre_group      = "https://attack.mitre.org/groups/G0016/"
	strings:
            $a1 = ".mp3" ascii wide nocase
            $a2 = "blank.pdf" ascii wide nocase
            $a3 = "Rock" ascii wide nocase
            $a4 = "vcruntime140.dll" ascii wide nocase

            $b1 = "RcvAddQueuedResolution" ascii wide nocase
            $b2 = "RcvResolution" ascii wide nocase
            $b3 = "AdobeAcroSup" ascii wide nocase
            $b4 = "AcroSup" ascii wide nocase
	condition:
		uint16(0) == 0x5a4d and ((filesize < 800KB) and all of ($a*) and any of ($b*))
}


// --- Upstream Source: https://raw.githubusercontent.com/InQuest/yara-rules-vt/main/Base64_Encoded_Powershell_Directives.yar ---
rule Base64_Encoded_Powershell_Directives
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects base64 encoded Powershell directives."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "https://inquest.net/blog/2019/07/19/base64-encoded-powershell-pivots"
        labs_reference = "https://labs.inquest.net/dfi/sha256/3b8235b67c4b67ea782b49388c5166786fb9d7a5b5096150b1c10e53f1d01738"
        labs_pivot     = "https://labs.inquest.net/dfi/search/alert/Base64%20Encoded%20Powershell%20Directives"
        samples        = "https://github.com/InQuest/malware-samples/tree/master/2019-07-Base64-Encoded-Powershell-Directives"

    strings:
        // NOTE: these regular expressions were generated via https://labs.inquest.net/tools/yara/b64-regexp-generator

        // Copy-Item
        $enc01 = /(Q\x32\x39weS\x31JdGVt[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]Db\x33B\x35LUl\x30ZW[\x30-\x33]|[\x2b\x2f-\x39A-Za-z][\x30EUk]NvcHktSXRlb[Q-Za-f])/

        // ForEach-Object
        $enc02 = /(Rm\x39yRWFjaC\x31PYmplY\x33[Q-T]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]Gb\x33JFYWNoLU\x39iamVjd[A-P]|[\x2b\x2f-\x39A-Za-z][\x30EUk]ZvckVhY\x32gtT\x32JqZWN\x30[\x2b\x2f-\x39A-Za-z])/

        // Get-ChildItem
        $enc03 = /(R\x32V\x30LUNoaWxkSXRlb[Q-Za-f]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]HZXQtQ\x32hpbGRJdGVt[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x30EUk]dldC\x31DaGlsZEl\x30ZW[\x30-\x33])/

        // Get-ItemPropertyValue
        $enc04 = /(R\x32V\x30LUl\x30ZW\x31Qcm\x39wZXJ\x30eVZhbHVl[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]HZXQtSXRlbVByb\x33BlcnR\x35VmFsdW[U-X]|[\x2b\x2f-\x39A-Za-z][\x30EUk]dldC\x31JdGVtUHJvcGVydHlWYWx\x31Z[Q-Za-f])/

        // Get-Random
        $enc05 = /(R\x32V\x30LVJhbmRvb[Q-Za-f]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]HZXQtUmFuZG\x39t[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x30EUk]dldC\x31SYW\x35kb\x32[\x30-\x33])/

        // Join-Path
        $enc06 = /(Sm\x39pbi\x31QYXRo[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]Kb\x32luLVBhdG[g-j]|[\x2b\x2f-\x39A-Za-z][\x30EUk]pvaW\x34tUGF\x30a[A-P])/

        // Move-Item
        $enc07 = /(TW\x39\x32ZS\x31JdGVt[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]Nb\x33ZlLUl\x30ZW[\x30-\x33]|[\x2b\x2f-\x39A-Za-z][\x30EUk]\x31vdmUtSXRlb[Q-Za-f])/

        // New-Item
        $enc08 = /(TmV\x33LUl\x30ZW[\x30-\x33]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]OZXctSXRlb[Q-Za-f]|[\x2b\x2f-\x39A-Za-z][\x30EUk]\x35ldy\x31JdGVt[\x2b\x2f-\x39A-Za-z])/

        // New-Object
        $enc09 = /(TmV\x33LU\x39iamVjd[A-P]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]OZXctT\x32JqZWN\x30[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x30EUk]\x35ldy\x31PYmplY\x33[Q-T])/

        // Out-String
        $enc10 = /(T\x33V\x30LVN\x30cmluZ[\x2b\x2f-\x39w-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]PdXQtU\x33RyaW\x35n[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x30EUk]\x39\x31dC\x31TdHJpbm[c-f])/

        // Remove-Item
        $enc11 = /(UmVtb\x33ZlLUl\x30ZW[\x30-\x33]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]SZW\x31vdmUtSXRlb[Q-Za-f]|[\x2b\x2f-\x39A-Za-z][\x31FVl]JlbW\x39\x32ZS\x31JdGVt[\x2b\x2f-\x39A-Za-z])/

        // Select-Object
        $enc12 = /(U\x32VsZWN\x30LU\x39iamVjd[A-P]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]TZWxlY\x33QtT\x32JqZWN\x30[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x31FVl]NlbGVjdC\x31PYmplY\x33[Q-T])/

        // Sort-Object
        $enc13 = /(U\x32\x39ydC\x31PYmplY\x33[Q-T]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]Tb\x33J\x30LU\x39iamVjd[A-P]|[\x2b\x2f-\x39A-Za-z][\x31FVl]NvcnQtT\x32JqZWN\x30[\x2b\x2f-\x39A-Za-z])/

        // Split-Path
        $enc14 = /(U\x33BsaXQtUGF\x30a[A-P]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]TcGxpdC\x31QYXRo[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x31FVl]NwbGl\x30LVBhdG[g-j])/

        // Test-Path
        $enc15 = /(VGVzdC\x31QYXRo[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]UZXN\x30LVBhdG[g-j]|[\x2b\x2f-\x39A-Za-z][\x31FVl]Rlc\x33QtUGF\x30a[A-P])/

        // Write-Host
        $enc16 = /(V\x33JpdGUtSG\x39zd[A-P]|[\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx]Xcml\x30ZS\x31Ib\x33N\x30[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x31FVl]dyaXRlLUhvc\x33[Q-T])/

        // [Convert]::FromBase64String
        $enc17 = /([\x2b\x2f-\x39A-Za-z][\x2b\x2f-\x39A-Za-z][\x31\x35\x39BFJNRVZdhlptx][\x30\x32Dlu-vy][O]jpGcm\x39tQmFzZTY\x30U\x33RyaW\x35n[\x2b\x2f-\x39A-Za-z]|[\x2b\x2f-\x39A-Za-z][\x30\x32-\x33EG-HUW-Xkm-n][\x34\x38IMQUY]\x36OkZyb\x32\x31CYXNlNjRTdHJpbm[c-f]|[QZb-d][DTjz]o\x36RnJvbUJhc\x32U\x32NFN\x30cmluZ[\x2b\x2f-\x39w-z])/

    condition:
            any of ($enc*)
}


// --- Upstream Source: https://raw.githubusercontent.com/InQuest/yara-rules-vt/main/Controlword_Whitespace_RTF.yar ---
rule Controlword_Whitespace_RTF
{
    meta:
        author         = "InQuest Labs"
        description    = "This rule detects multiple instances of whitespace characters in the OBJDATA control word in an RTF document."
        created_date   = "2022-03-15"
        updated_date   = "2022-03-15"
        blog_reference = "InQuest Internal Research"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "c4754d2d7e02c50de6e0551d6b0567ec3c48d6ae45d9e62ad62d544f66cf131c"

    strings:
		$rtf_magic = "{\\rt"  // note that {\rtf1 is not required

		$re1 = /\x7b[^\x7d]*\\objdata[ \t\r\n]+[a-f0-9\x2e\x2d\r\n\x5c]{0,100}[ \t\r\n]{9,}[a-f0-9\x2e\x2d\r\n\x5c]{0,100}[ \t\r\n]{6,}[a-f0-9\x2e\x2d\r\n\x5c]{0,100}[ \t\r\n]{6}/ nocase wide ascii
		//$re1 is looking within \objdata controll word for at least two instances of whitespace characters (9 or more and 6 or more) in between the contents
	condition:
			
		$rtf_magic in (0..30) and all of ($re*)

}
