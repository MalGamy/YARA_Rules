rule detect_vidar: Vidar
{
    meta:
	description = "detect_Vidar_Stealer"
	author = "@malgamy12"
	date = "11/13/2022"
	license = "DRL 1.1"
        hash = "011e2fb7319d8962563dd48de0fec1400a20c9fdcc7ff0766fdea47959ab6805"
        

    strings:
        $s1 = "*wallet*.dat" ascii

        $a1 = "Autofill\\%s_%s.txt" ascii
        $a2 = "History\\%s_%s.txt" ascii
        $a3 = "Downloads\\%s_%s.txt" ascii

        $b1 = "screenshot.jpg" ascii
        $b2 = "Data\\*.dll" ascii

        $chunk_1 = {8B C8 33 D2 8B C5 F7 F1 8B 44 24 ?? 8B 4C 24 ?? [2] 8A 04 02 32 04 19 88 03}
    condition:
        uint16(0) == 0x5A4D and $s1 and ((1 of ($a*) and $chunk_1 ) or (1 of ($b*) and $chunk_1))

}

