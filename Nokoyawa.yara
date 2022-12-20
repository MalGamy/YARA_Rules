rule Nokoyawa_ransomware: Nokoyawa
{
    meta:
	description = "Detect_Nokoyawa_ransomware"
	author = "@malgamy12"
	date = "20/12/2022"
	license = "DRL 1.1"
        hash = "7095beafff5837070a89407c1bf3c6acf8221ed786e0697f6c578d4c3de0efd6"
        hash = "47c00ac29bbaee921496ef957adaf5f8b031121ef0607937b003b6ab2a895a12"
        hash = "259f9ec10642442667a40bf78f03af2fc6d653443cce7062636eb750331657c4"
  
                
    strings:
        
        $pdb = "deps\\noko.pdb" ascii

        $s1 = "How to run:" ascii
        $s2 = "--config <base64 encoded config> (to start full encryption)" ascii
        $s3 = "--config <base64 encoded config> --file <filePath>" ascii
        $s4 = "CIS lang detected! Stop working" ascii
        $s5 = "config isn't configurated to load hidden drives" ascii
        $s6 = "ENCRYPT_NETWORKYour config isn't configurated to encrypt network shares" ascii
        $s7 = "Your config isn't configurated to delete shadow copies" ascii
        $s8 = "Successfully deleted shadow copies from" ascii
        
    condition:
        uint16(0) == 0x5A4D and ($pdb or 3 of ($s*))
}
