rule Detect_lumma_stealer: lumma
{
    meta:
	    description = "Detect_lumma_stealer"
	    author = "@malgamy12"
	    date = "2023/1/7"
                
    strings:
        
        $op = {0B C8 69 F6 [4] 0F B6 47 ?? C1 E1 ?? 0B C8 0F B6 07 C1 E1 ?? 83 C7 ?? 0B C8 69 C9 [4] 8B C1 C1 E8 ?? 33 C1 69 C8 [4] 33 F1}


    condition:
        uint16(0) == 0x5A4D and $op
}





