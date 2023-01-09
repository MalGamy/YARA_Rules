rule Detect_lumma_stealer: lumma
{
    meta:
    
	description = "Detect_lumma_stealer"
	author = "@malgamy12"
	date = "2023/1/7"
	license = "DRL 1.1"
        hash = "61b9701ec94779c40f9b6d54faf9683456d02e0ee921adbb698bf1fee8b11ce8"
        hash = "277d7f450268aeb4e7fe942f70a9df63aa429d703e9400370f0621a438e918bf"
        hash = "9b742a890aff9c7a2b54b620fe5e1fcfa553648695d79c892564de09b850c92b"
        hash = "60247d4ddd08204818b60ade4bfc32d6c31756c574a5fe2cd521381385a0f868"
                
    strings:
         
        $s1 = "- PC:" ascii 
        $s2 = "- User:" ascii
        $s3 = "- Screen Resoluton:" ascii
        $s4 = "- Language:" ascii
        
        $op = {0B C8 69 F6 [4] 0F B6 47 ?? C1 E1 ?? 0B C8 0F B6 07 C1 E1 ?? 83 C7 ?? 0B C8 69 C9 [4] 8B C1 C1 E8 ?? 33 C1 69 C8 [4] 33 F1}

    condition:
        uint16(0) == 0x5A4D and $op and all of ($s*)
}






