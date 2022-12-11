rule colibri_loader: colibri
{
    meta:
	description = "Detect_colibri_loader"
	author = "@malgamy12"
	date = "7/12/2022"
	license = "DRL 1.1"
        hash= "59f5e517dc05a83d35f11c6682934497"
        hash= "7615231dd8463c48f9dc66b67da68f49"
        hash= "7f697936757ced404c2a7515ccfe426b"
        hash= "85c3a80b85fceae0aba419b8b62ff831"
        hash= "f1bbf3a0c6c52953803e5804f4e37b15"
        hash= "7207e37226711374827d0f877b607b0f"
        hash= "7eb0b86bc4725d56c499939ab06212cf"
        hash= "21ec2cac8a3511f6a3d1ade20d5c1e38"
                
    strings:
        $p1 = {0F B7 06 0F B7 4E ?? 03 D0 8B C2 83 C6 ?? C1 E0 ?? 33 C8 C1 E1 ?? 33 D1 8B C2 C1 E8 ?? 03 D0 83 EB}
        $p2 = {8B C2 C1 E0 ?? 33 D0 8B C2 C1 E8 ?? 03 D0 8B C2 C1 E0 ?? 33 D0 8B C2 C1 E8 ?? 03 D0 8B C2 C1 E0 ?? 33 D0 8B C2 C1 E8 ?? 03 C2}
        $p3 = {33 D2 8B C3 F7 75 ?? 66 8B 04 56 66 33 04 0F 43 66 89 01 8D 49 ?? 3B 5D}
        
    condition:
        uint16(0) == 0x5A4D and all of them
}
