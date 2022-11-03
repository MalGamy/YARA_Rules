rule detect_Lumma_stealer: Lumma 
{
	meta:
		description = "detect_Lumma_stealer"
		author = "@malgamy12"
		date = "2022-11-3"

    strings:
        $m1 = "LummaC\\Release\\LummaC.pdb" ascii fullword

        $s1 = "Cookies.txt" ascii
        $s2 = "Autofills.txt" ascii
        $s3 = "ProgramData\\config.txt" ascii
        $s4 = "ProgramData\\softokn3.dll" ascii
        $s5 = "ProgramData\\winrarupd.zip" ascii
        

        $chunk_1 = {
            C1 E8 ??          
            33 C6             
            69 C8 ?? ?? ?? ?? 
            5F                
            5E                
            8B C1             
            C1 E8 ??          
        }
        

    condition:
        $m1 or (4 of ($s*) and $chunk_1 )
}




