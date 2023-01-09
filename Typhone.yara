rule detect_Typhon_Stealer: Typhon_Stealer
{
    meta:
	description = "detect_Typhon_Stealer"
	author = "@malgamy12"
	date = "15/11/2022"
	license = "DRL 1.1"
        hash1 = "A12933AB47993F5B6D09BEC935163C7F077576A8B7B8362E397FE4F1CE4E791C"
        

    strings:
        $s0 = "\\NetworkInformation.txt" wide
        $s1 = "\\UserDetails.txt" wide
        $s2 = "\\HardwareDetails.txt" wide
        $s3 = "TaskKill /F /IM" wide
        $s4  = "Timeout /T 2 /Nobreak" wide
        $s5  = "### BlackListedCountries ###" wide
        $s6  = "TyphonStealer_Reborn_v1" wide
        $s7  = "t.me/typhon_shop" wide

        
    condition:
        uint16(0) == 0x5A4D  and (all of them)

}
