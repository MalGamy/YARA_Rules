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
            C1 E8 ??          // shr eax, 0xd
            33 C6             // xor eax, esi
            69 C8 ?? ?? ?? ?? // imul ecx, eax, 0x5bd1e995
            5F                // pop edi
            5E                // pop esi
            8B C1             // mov eax, ecx
            C1 E8 ??          // shr eax, 0xf
        }
        

    condition:
        $m1 or (4 of ($s*) and $chunk_1 )
}




