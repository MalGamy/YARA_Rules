rule detect_Raccoon_Stealer_v2: Raccoon_Stealer_v2 
{
	meta:
		description = "detect_Raccoon_Stealer_v2"
		author = "@malgamy12"
		date = "15/11/2022"
        hash1 = "0123b26df3c79bac0a3fda79072e36c159cfd1824ae3fd4b7f9dea9bda9c7909"
        

    strings:
        $s0 = "\\ffcookies.txt" wide
        $s1 = "wallet.dat" wide
        $s2 = "Network\\Cookies" wide
        $s3 = "Wn0nlDEXjIzjLlkEHYxNvTAXHXRteWg0ieGKVyD52CvONbW7G91RvQDwSZi/N2ISm" ascii 

        $op1 = {6B F3 ?? 03 F7 8B 7D ?? [3] A5}
        $op2 = {8A 0C 86 8B 45 ?? 8B 7D ?? 32 0C 38 8B 7D ?? 8B 86 [4] 88 0C 07 8B C7 8B 7D ?? 40}

        
    condition:
        uint16(0) == 0x5A4D  and (all of them)

}