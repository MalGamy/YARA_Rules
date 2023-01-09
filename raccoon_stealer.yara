rule detect_Raccoon_Stealer_v2: Raccoon_Stealer_v2 
{
    meta:
	description = "detect_Raccoon_Stealer_v2"
	author = "@malgamy12"
	date = "16/11/2022"
	license = "DRL 1.1"
        hash = "0123b26df3c79bac0a3fda79072e36c159cfd1824ae3fd4b7f9dea9bda9c7909"
	hash = "0c722728ca1a996bbb83455332fa27018158cef21ad35dc057191a0353960256"
	hash = "048c0113233ddc1250c269c74c9c9b8e9ad3e4dae3533ff0412d02b06bdf4059"
	hash = "89a718dacc3cfe4f804328cbd588006a65f4dbf877bfd22a96859bf339c6f8bc"
        hash = "516c81438ac269de2b632fb1c59f4e36c3d714e0929a969ec971430d2d63ac4e"
        hash = "0c722728ca1a996bbb83455332fa27018158cef21ad35dc057191a0353960256"
        hash = "3ae9d121aa4b989118d76e8b0ff941b9b72ccac746de8b3a5d9f7d037361be53"
        hash = "bd8c1068561d366831e5712c2d58aecb21e2dbc2ae7c76102da6b00ea15e259e"
        hash = "960ce3cc26c8313b0fe41197e2aff5533f5f3efb1ba2970190779bc9a07bea63"
        hash = "bc15f011574289e46eaa432f676e59c50a9c9c42ce21332095a1bd68de5f30e5"
        

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
