rule detect_rifdoor: rifdoor
{
	meta:
	description = "detect_rifdoor"
	author = "@malgamy12"
	date = "2022/11/11"
	license = "DRL 1.1"
        hash1 = "19b2144927bd071e30df9fce5f3d49f1"
        hash2 = "d8ba4b4bfc5e0877fa8e8c1b26876ea6"
        hash3 = "d94d6f773c0ed5514d3e571e4b3681ba"
        hash4 = "5aca1e4ec64ba417d1b0ebea88bdd06e"
        hash5 = "45f8d44cba70520ca2ea97427ddaab3e"
        hash6 = "d3b2956904bed8c8146b8bb556b8911a"
        hash7 = "e4c4c9abdd8613afa17f58d721039a46"
        hash8 = "cf847663a7a9d6ddbe3a1f0d5e5236b6"
        hash9 = "01a0b932d82ed3b78ccfb2bb5826c32f"
        hash10 = "c6687e1fab97b2d7433a5e51fcf2aa30"

    strings:
        $pdb = "rifle.pdb" ascii

        $s1 = "MUTEX394039_4830023" ascii
        $s2 = "CMD:%s %s %d/%d/%d %d:%d:%d" ascii
	$s3 = "/c del /q \"%s\" >> NUL" ascii

        $chunk_1 = {80 32 ?? 41 80 39 ?? 8B D1 75} // xor operation

        
    condition:
        uint16(0) == 0x5A4D  and ($pdb  or  (2 of ($s*) and $chunk_1 ))

}
