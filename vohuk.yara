rule Vohuk_ransomware: Vohuk
{
    meta:
	    description = "Detect_Vohuk_ransomware"
	    author = "@malgamy12"
	    date = "8/12/2022"
        hash= "59f5e517dc05a83d35f11c6682934497"
  
                
    strings:
        $p1 = {B8 [4] 8B CE F7 EE C1 FA ?? 8B C2 C1 E8 ?? 03 C2 69 C0 [4] 2B C8 83 C1 ?? 66 31 4C 75 ?? 46 83 FE ?? 72}
        $p2 = {8B 34 B8 BA ?? ?? ?? ?? 0F BE 04 1E 03 F3}
        
    condition:
        uint16(0) == 0x5A4D and all of them
}