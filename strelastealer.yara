rule detect_StrelaStealer: StrelaStealer
{
	meta:
		description = "detect_StrelaStealer"
		author = "@malgamy12"
		date = "2022/11/12"
        hash1 = "19b2144927bd071e30df9fce5f3d49f1"
        

    strings:
        $pdb = "StrelaDLLCompile.pdb" ascii

        $s1 = "4f3855aa-af7e-4fd2-b04e-55e63653d2f7" ascii
        $s2 = "StrelaDLLCompile.dll" ascii

        $chunk_1 = {33 D2 8B C7 F7 F3 8D 04 2E 83 C7 ?? 83 C6 ?? 8A 92 [4] 30 56 ?? 33 D2 F7 F3 8A 82 [4] 30 46 ?? 83 FF ??} 

        
    condition:
        uint16(0) == 0x5A4D  and ($pdb  or  (1 of ($s*) and $chunk_1 ))

}