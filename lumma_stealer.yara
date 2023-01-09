rule detect_Lumma_stealer: Lumma 
{
	meta:
		description = "detect_Lumma_stealer"
		author = "@malgamy12"
		date = "2022-11-3"
		license = "DRL 1.1"
		hunting = "https://www.hybrid-analysis.com/sample/f18d0cd673fd0bd3b071987b53b5f97391a56f6e4f0c309a6c1cee6160f671c0"
		hash1 = "19b937654065f5ee8baee95026f6ea7466ee2322"
                hash2 = "987f93e6fa93c0daa0ef2cf4a781ca53a02b65fe"
                hash3 = "70517a53551269d68b969a9328842cea2e1f975c"
                hash4 = "9b7b72c653d07a611ce49457c73ee56ed4c4756e"
                hash5 = "4992ebda2b069281c924288122f76556ceb5ae02"
                hash6 = "5c67078819246f45ff37d6db81328be12f8fc192"
                hash7 = "87fe98a00e1c3ed433e7ba6a6eedee49eb7a9cf9"

    strings:
        $m1 = "LummaC\\Release\\LummaC.pdb" ascii fullword

        $s1 = "Cookies.txt" ascii
        $s2 = "Autofills.txt" ascii
        $s3 = "ProgramData\\config.txt" ascii
        $s4 = "ProgramData\\softokn3.dll" ascii
        $s5 = "ProgramData\\winrarupd.zip" ascii
        

        $chunk_1 = {C1 E8 ?? 33 C6 69 C8 ?? ?? ?? ?? 5F 5E 8B C1 C1 E8 ??}

    condition:
        $m1 or (4 of ($s*) and $chunk_1 )
}




