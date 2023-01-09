rule Cova_malware: Cova
{
    meta:
	description = "Detect_Cova_malware"
	author = "@malgamy12"
	date = "2023/1/9"
        license = "DRL 1.1"
        hash = "a1ae4a7440c7f2f0d03c6f2e05ff97b875e8295cf2b340b96fdda919af6c7eb5"

  
                
    strings:
	    
        $s1 = "Release\\orval.pdb" ascii 

        $op1 = {49 8B C0 83 E0 ?? 8A 0C 04 43 32 0C 01 41 32 C8 43 88 0C 01 49 FF C0 4C 3B C2 72}
        
        
    condition:
        uint16(0) == 0x5A4D and all of them
}



