rule Detect_Tofsee: Tofsee
{
    meta:
	description = "Detect_Tofsee"
	author = "@malgamy12"
	date = "21/11/2022"
	license = "DRL 1.1"
        hash = "96baba74a907890b995f23c7db21568f7bfb5dbf417ed90ca311482b99702b72"
        

    strings:
        $a1 = "%s, %u %s %u %.2u:%.2u:%.2u %s%.2u%.2u" ascii
        $a2 = "start_srv" ascii
        $a3 = "work_srv" ascii
        $a4 = "flags_upd" ascii
        $a5 = "lid_file_upd" ascii
        $a6 = "born_date" ascii
        $a7 = "net_type" ascii
        
        $op = {8B 45 ?? 57 8B 7D ?? B1 ?? 85 FF 74 ?? 56 8B 75 ?? 2B F0 8A 14 06 32 55 ?? 88 10 8A D1 02 55 ?? F6 D9 00 55 ?? 40 4F 75 ?? 5E 8B 45 ?? 5F}
        
    condition:
        uint16(0) == 0x5A4D  and ((5 of ($a*) and $op))
}

