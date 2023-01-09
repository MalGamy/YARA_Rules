rule detect_silence_Downloader: silence Downloader 
{
	meta:
	 description = "detect_silence_Downloader"
	 author = "@malgamy12"
	 date = "8/11/2022"
	 license = "DRL 1.1"
	 sample1 = "BAE2737C39C0DEF9603EF9E6CD4921BF641FAB91"
         sample2 = "A7421FDA552316FD89FA545D1815DE0AF8EC2858"


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
