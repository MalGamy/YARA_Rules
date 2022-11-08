rule detect_silence_Downloader: silence Downloader 
{
	meta:
		description = "detect_silence_Downloader"
		author = "@malgamy12"
		date = "2022-11-7"

    strings:

        $s1 = "MicrosoftUpdte" ascii
        $s2 = "IntelSofts" ascii
		$s3 = "php?name=" ascii
        $s4 = "SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $s5 = "ShellExecuteA" ascii
        $s6 = "InternetOpenA" ascii
        $s7 = "CreateFileA"  ascii 
        $s8 = "CreateProcessA" ascii
        
    condition:
        uint16(0) == 0x5A4D and (7 of ($s*))
}
