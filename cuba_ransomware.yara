rule cuba_ransomware: cuba
{
    meta:
	description = "Detect_cuba_ransomware"
	author = "@malgamy12"
	date = "24/11/2022"
	license = "DRL 1.1"
        hash = "c2aad237b3f4c5a55df88ef26c25899fc4ec8170"
        hash = "4b41a1508f0f519396b7c14df161954f1c819e86"
        hash = "d5fe48b914c83711fe5313a4aaf1e8d80533543d"
        hash = "159b566e62dcec608a3991100d6edbca781d48c0"
        hash = "e1cae0d2a320a2756ae1ee5d37bfe803b39853fa"
        hash = "6f1d355b95546f0a5a09f7fd0b85fc9658e87813"
        hash = "25da0849207beb5695c8d9826b585b8cda435eba"
        hash = "3997d19f38ce14b7643c1ad8d6a737990b444215"
        hash = "f008e568c313b6f41406658a77313f89df07017e"
        hash = "7e42b668fd2ca96b05f39d5097943a191f1010f4"
        

    strings:
        $p1 = {C1 8D 73 ?? 99 83 E2 ?? 03 C2 C1 F8 ?? 8D 04 45 [4] 89 83 [4] 0F B6 0F 0F B6 47 ?? C1 E1 ?? 0B C8 0F B6 47 ?? C1 E1 ?? 0B C8 0F B6 47 ?? C1 E1 ?? 0B C8 89 0B 0F B6 47 ?? 89 4D ?? 0F B6 4F ?? C1 E1 ?? 0B C8 0F B6 47 ?? C1 E1 ?? 0B C8 0F B6 47 ?? C1 E1 ?? 0B C8 89 0E 0F B6 4F ?? 0F B6 47 ?? C1 E1 ?? 0B C8 0F B6 47 ?? C1 E1 ?? 0B C8 0F B6 47 ?? C1 E1 ?? 0B C8 89 4B ?? 0F B6 4F ?? 0F B6 47 ?? C1 E1 ?? 0B C8 0F B6 47 ?? C1 E1 ?? 0B C8 0F B6 47 ?? C1 E1 ?? 0B C8 8B 45 ?? 89 4D ?? 89 4B}
        $p2 = {5D ?? 8B C3 C1 E8 ?? 0F B6 D0 8B C3 C1 E8 ?? 0F B6 C8 8B 04 95 [4] 33 04 8D [4] 8B CB C1 E9 ?? 33 04 8D [4] 0F B6 CB 5B 33 04 8D}
        $p3 = {8B 75 ?? 8B C6 C1 E8 ?? 0F B6 C8 8B 45 ?? C1 E8 ?? 0F B6 C0 8B 0C 8D [4] 8B 55 ?? 33 0C 85 [4] 8B C2 C1 E8 ?? 33 0C 85 [4] 8B 45 ?? 0F B6 C0 33 0C 85 [4] 33 0F 8B 45 ?? C1 E8 ?? 89 4D ?? 0F B6 C8 8B C6 C1 E8 ?? 0F B6 C0 8B 0C 8D [4] 33 0C 85 [4] 8B 45 ?? C1 E8 ?? 33 0C 85 [4] 0F B6 C2 33 0C 85 [4] 33 4F ?? 8B 45 ?? C1 E8 ?? 89 4D ?? 0F B6 C8 8B C2 C1 E8 ?? 0F B6 C0 C1 EA ?? 8B 1C 8D [4] 8B 4D ?? 33 1C 85 [4] 8B C6 C1 E8 ?? 33 1C 85 [4] 0F B6 C1 C1 E9 ?? 0F B6 C9 33 1C 85 [4] 33 5F ?? 0F B6 C2 8B 14 8D [4] 33 14 85 [4] 8B 45 ?? C1 E8 ?? 33 14 85 [4] 8B C6 0F B6 C0 33 14 85 [4] 8B C3 33 57 ?? C1 E8 ?? 0F B6 C8 8B 45 ?? C1 E8 ?? 0F B6 C0 8B 0C 8D [4] 33 0C 85 [4] 8B 45 ?? C1 E8 ?? 33 0C 85 [4] 0F B6 C2 33 0C 85 [4] 8B C2 33 4F ?? C1 E8 ?? 89 4D ?? 0F B6 C8 8B C3 C1 E8 ?? 8B 0C 8D [4] 0F B6 C0 33 0C 85 [4] 8B 45 ?? C1 E8 ?? 33 0C 85 [4] 8B 45 ?? 0F B6 C0 33 0C 85 [4] 8B C2 33 4F ?? C1 E8 ?? 89 4D ?? 0F B6 C8 8B 45 ?? C1 E8 ?? 0F B6 C0 8B 0C 8D [4] C1 EA ?? 33 0C 85 [4] 8B C3 C1 E8 ?? 33 0C 85 [4] 89 4D ?? 8B 4D ?? 8B 75 ?? 0F B6 C1 C1 E9 ?? 0F B6 C9 33 34 85 [4] 8B C6 89 75 ?? 33 47 ?? 8B 0C 8D [4] 89 45 ?? 8B 45 ?? C1 E8 ?? 0F B6 C0 33 0C 85 [4] 33 0C 95 [4] 0F B6 C3 33 0C 85 [4] 33 4F ?? 83 C7 ?? 83 6D}
        
    condition:
        uint16(0) == 0x5A4D and all of them
}
