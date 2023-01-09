rule detect_Mars_Stealer: Mars_Stealer
{
    meta:
	description = "detect_Mars_Stealer"
	author = "@malgamy12"
	date = "12/14/2022"
	license = "DRL 1.1"
        comment = "frist op1 to detect old version with strings and (op2) to detect new version"
        old_version_hash = "7da3029263bfbb0699119a715ce22a3941cf8100428fd43c9e1e46bf436ca687"
        ne_version_hash = "0d6470143f1102dbeb8387ded8e73cedbc3aece7a3594255d46c9852f87ac12f"
        

    strings:
        $op1 = { 0F B7 05 [4] 0F B7 0D [4] C1 F9 ?? 33 C1 0F B7 15 [4] C1 FA ?? 33 C2 0F B7 0D [4] C1 F9 ?? 33 C1 83 E0 ?? A3 [4] 0F B7 15 [4] D1 FA A1 [4] C1 E0 ?? 0B D0 66 89 15 [4] 0F B7 05 }
        $op2 = { 0F BE 19 8B 55 ?? 52 E8 [4] 83 C4 ?? 8B C8 8B 45 ?? 33 D2 F7 F1 8B 45 ?? 0F BE 0C 10 33 D9 8B 55 ?? 03 55 ?? 88 1A }
		

        $s1 = "86223203794583053453" ascii
        $s2 = "image/jpeg" wide 
    

        
    condition:
        uint16(0) == 0x5A4D  and (1 of ($op*)) or (all of ($s*))
}
