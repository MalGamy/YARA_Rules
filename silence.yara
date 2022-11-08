rule detect_silence_Downloader: silence Downloader 
{
	meta:
	 description = "detect_silence_Downloader"
	 author = "@malgamy12"
	 date = "2022-11-7"

    strings:

        $intel = "IntelSofts" ascii
	
	$s1 = "MicrosoftUpdte" ascii
	$s2 = "php?name=" ascii
        $s3 = "SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $s4 = "ShellExecuteA" ascii
        $s5 = "InternetOpenA" ascii
        $s6 = "CreateFileA"  ascii 
        $s7 = "CreateProcessA" ascii
        
    condition:
        uint16(0) == 0x5A4D and $intel or (6 of ($s*))
}
