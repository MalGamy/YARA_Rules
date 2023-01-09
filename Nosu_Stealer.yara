rule Nosu_stealer: Nosu
{
    meta:
	description = "Detect_Nosu_stealer"
	author = "@malgamy12"
	date = "2023/1/9"
        license = "DRL 1.1"
        hash = "6499cadaea169c7dfe75b55f9c949659af49649a10c8b593a8db378692a11962"
        hash = "e227246cbebf72eb2867ef21b1b103ec07ddd87f4f8a5ac89a47536d5b831f6d"
        hash = "3d18b9c312abaa8dd93dc0d1abfdc97e72788100fb1effb938b5f6f4fd3b59eb"
        hash = "e513f5e424371cce491ae28d45aaa7e361f370c790dc86bb33dc9313b3660ac3"
  
                
    strings:
	    $s1 = "release\\lilly.pdb" ascii

		
        $op1 = {33 D2 8B C3 F7 F7 8A C3 24 ?? 32 04 32 30 04 19 43 8B 4C 24 ?? 3B DD 72}
        $op2 = {8B 86 [4] 80 34 08 ?? 41 8B 86 [4] 3B C8 72}
	$op3 = {69 D2 [4] 33 C9 42 8B C2 0F A4 C1 ?? 30 0C 1E 46}
        
    condition:
        uint16(0) == 0x5A4D and ($s1 or all of ($op*))
}
