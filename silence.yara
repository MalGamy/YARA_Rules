rule detect_silence_Downloader: silence Downloader 
{
	meta:
	 description = "detect_silence_Downloader"
	 author = "@malgamy12"
	 date = "8/11/2022"
	 sample1 = "4ea01c831c24b70b75bcdf9b33ad9c69e097cbadafd30599555a43a1f412455d"
         sample2 = "6514742199e8fd5b6e09fcdf550706ecaab46cf8cd8da8550e3d5042a1bee127"
         sample3 = "4fd37dc5eaa90a02a53b2c2df42c21e6017a925b65cedf62c69aa757be49e144"
         sample4 = "8901d01bbf3aa2ced5fe2232493278ea56207ec6b0a9f17d8ba94b5095e28835"

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
