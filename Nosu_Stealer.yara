rule Nosu_stealer: Nosu
{
    meta:
	    description = "Detect_Nosu_stealer"
	    author = "@malgamy12"
	    date = "2023/1/9"
        hash= "e27b637abe523503b19e6b57b95489ea"
  
                
    strings:
	    $s1 = "release\\lilly.pdb" ascii

		
        $op1 = {33 D2 8B C3 F7 F7 8A C3 24 ?? 32 04 32 30 04 19 43 8B 4C 24 ?? 3B DD 72}
        $op2 = {8B 86 [4] 80 34 08 ?? 41 8B 86 [4] 3B C8 72}
		$op3 = {69 D2 [4] 33 C9 42 8B C2 0F A4 C1 ?? 30 0C 1E 46}
        
    condition:
        uint16(0) == 0x5A4D and ($s1 or all of ($op*))
}