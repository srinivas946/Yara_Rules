/* YARA RULE RELATED TO APT-41
   FOR DETAILED EXPLANATION REFER : www.cybersecpy.in
   */
   
 rule APT41
 {
	meta:
		author = "cybersecpy"
		last_modified = "31-03-2020"
		description = "YARA Rules based on Hashes (MD5, SHA-1, SHA-256)"
		refer = "www.cybersecpy.in"
	
	strings:
		/* CRACKSHOT MALWRE */
		//MD5
		$C1 = 04fb0ccf3ef309b1cd587f609ab0e81e
		$C2 = 0b2e07205245697a749e422238f9f785
		$C3 = 272537bbd2a8e2a2c3938dc31f0d2461
		$C4 = dd792f9185860e1464b4346254b2101b
		$C5 = fcfab508663d9ce519b51f767e902806
		
		//SHA-1
		$C6 = 44260a1dfd92922a621124640015160e621f32d5
		$C7 = dde82093decde6371eb852a5e9a1aa4acf3b56ba
		$C8 = a045939f53c5ad2c0f7368b082aa7b0bd7b116da
		$C9 = a260dcf193e747cee49ae83568eea6c04bf93cb3
		$C10 = 8272c1f41f7c223316c0d78bd3bd5744e25c2e9f
		
		//SHA-256
		$C11 = 993d14d00b1463519fea78ca65d8529663f487cd76b67b3fd35440bcdf7a8e31
		$C12 = 049a2d4d54c511b16f8bc33dae670736bf938c3542f2342192ad877ab38a7b5d
		$C13 = d00b3edc3fe688fa035f1b919ef6e8f451a9c2197ef83d9bac3fa3af5e752243
		$C14 = 7096f1fdefa15065283a0b7928d1ab97923688c7974f98a33c94de214c675567
		$C15 = c667c9b2b9741247a56fcf0deebb4dc52b9ab4c0da6d9cdaba5461a5e2c86e0c
		
		/* GEARSHIFT MALWARE */
		//MD5
		$G1 = 5b26f5c7c367d5e976aaba320965cc7f
		$G2 = f8c89ccd8937f2b760e6706738210744
		
		//SHA-1
		$G3 = c2fb50c9ef7ae776a42409bce8ef1be464654a4e
		$G4 = f3c222606f890573e6128fbeb389f37bd6f6bda3
		
		//SHA-256
		$G5 = 7e0c95fc64357f12e837112987333cdaf8c1208ef8c100649eba71f1ea90c1db
		$G6 = 4aa6970cac04ace4a930de67d4c18106cf4004ba66670cfcdaa77a4c4821a213 
		
		/* HIGHNOON MALWARE */
		//MD5
		$H1 = 46a557fbdce734a6794b228df0195474
		$H2 = 77c60e5d2d99c3f63f2aea1773ed4653
		$H3 = 849ab91e93116ae420d2fe2136d24a87
		$H4 = 36711896cfeb67f599305b590f195aec
		$H5 = 7d51ea0230d4692eeedc2d5a4cd66d2d
		$H6 = a0a96138b57ee24eed31b652ddf60d4e
		
		//SHA-1
		$H7 = 03de2118aac6f20786043c7ef0324ef01dcf4265
		$H8 = 5ee7c57dc84391f63eaa3824c53cc10eafc9e388
		$H9 = 1036a7088b060250bb66b6de91f0c6ac462dc24c
		$H10 = 41bac813ae07aef41436e8ad22d605f786f9e099
		$H11 = ad77a34627192abdf32daa9208fbde8b4ebfb25c
		$H12 = 3f1dee370a155dc2e8fb15e776821d7697583c75
		
		//SHA-256
		$H13 = 42d138d0938494fd64e1e919707e7201e6675b1122bf30ab51b1ae26adaec921
		$H14 = 7566558469ede04efc665212b45786a730055770f6ea8f924d8c1e324cae8691
		$H15 = 7cd17fc948eb5fa398b8554fea036bdb3c0045880e03acbe532f4082c271e3c5
		$H16 = 490c3e4af829e85751a44d21b25de1781cfe4961afdef6bb5759d9451f530994
		$H17 = 63e8ed9692810d562adb80f27bb1aeaf48849e468bf5fd157bc83ca83139b6d7
		$H18 = 79190925bd1c3fae65b0d11db40ac8e61fb9326ccfed9b7e09084b891089602d
		
		/* JUMPALL MALWARE */
		//MD5
		$J1 = ba08b593250c3ca5c13f56e2ca97d85e
		
		//SHA-1
		$J2 = adde0644a572ed593e8b0566698d4e3de0fefb8a
		
		//SHA-256
		$J3 = c51c5bbc6f59407286276ce07f0f7ea994e76216e0abe34cbf20f1b1cbd9446d
		
		/* POISONPLUG MALWARE */
		//MD5
		$P1 = 223e4cc4cf5ce049f300671697a17a01
		$P2 = 37e100dd8b2ad8b301b130c2bca3f1ea
		$P3 = 557ff68798c71652db8a85596a4bab72
		$P4 = 830a09ff05eac9a5f42897ba5176a36a
		$P5 = b0877494d36fab1f9f4219c3defbfb19
		$P6 = c8403fabda4d036a55d0353520e765c9
		$P7 = ff8d92dfbcda572ef97c142017eec658
		$P8 = ffd0f34739c1568797891b9961111464
		$P9 = 72584d6b7dd10c82d9118567b548b2b1
		$P10 = 97363d50a279492fda14cbab53429e75
		$P11 = a6c7db170bc7a4ee2cdb192247b59cd6
		
		//SHA-1
		$P12 = 5a85d1e19e0414fc59e454ccbaef0a3c6bb41268
		$P13 = f1a181d29b38dfe60d8ea487e8ed0ef30f064763
		$P14 = f067443c2c4d99dc6577006a2f105e51af731659
		$P15 = 1835c7751436cc199c55b42f34566d25fe6104ca
		$P16 = 1835c7751436cc199c55b42f34566d25fe6104ca
		$P17 = 32466d8d232d7b1801f456fe336615e6fa5e6ffb
		$P18 = 971bb08196bba400b07cf213345f55ce0a6eedc8
		$P19 = 2366d181a1697bcb4f368df397dd0533ab8b5d27
		$P20 = 4dc5fadece500ccd8cc49cfcf8a1b59baee3382a
		$P21 = d0429abec299ddfee7e1d9ccff1766afd4c0992b
		$P22 = 6f065eea36e28403d4d518b8e24bb7a915b612c3
		$P23 = 82072cb53416c89bfee95b239f9a90677a0848df
		
		//SHA-256
		$P24 = e65d39fa659f64a57ee13e8a638abd9031fa1486311d2782f32e979d5dee1ca5
		$P25 = 2eea29d83f485897e2bac9501ef000cc266ffe10019d8c529555a3435ac4aabd
		$P26 = 5d971ed3947597fbb7e51d806647b37d64d9fe915b35c7c9eaf79a37b82dab90
		$P27 = 70c03ce5c80aca2d35a5555b0532eedede24d4cc6bdb32a2c8f7e630bba5f26e
		$P28 = 3e6c4e97cc09d0432fbbbf3f3e424d4aa967d3073b6002305cd6573c47f0341f
		$P29 = 9283703dfbc642dd70c8c7667528552690e998bcb3f3374273c0b5c90c0d1366
		$P30 = f4d57acde4bc546a10cd199c70cdad09f576fdfe66a36b08a00c19ff6ae19661
		$P31 = 0055dfaccc952c99b1171ce431a02abfce5c6f8fb5dc39e4019b624a7d03bfcb
		$P32 = faedf9fef6edac2f0565882112b2eae14edda024239d3218a9fe9ac7e0b12db6
		$P33 = 462a02a8094e833fd456baf0a6d4e18bb7dab1a9f74d5f163a8334921a4ffde8
		$P34 = 92cb362ae8d24c05f368d13036534fe014344994d46031a0a8636a7ca0b792c6
		
		/* PHISHING PAYLOADS */
		//MD5
		$A1 = 5e87b09f9a3f1b728c9797560a38764b
		$A2 = 8c6cceae2eea92deb6f7632f949293f0
		
		//SHA-1
		$A3 = 67c957c268c1e56cc8eb34b02e5c09eae62680f5
		$A4 = b193ff40a98cd086f92893784d8896065faa3ee3
		
		//SHA-256
		$A5 = 5354c174e583e968f0ecf86cc20d59ecd6e0f9d21800428453b8db63f344f0f2
		$A6 = bae8f4f5fc959bff980d6a6d12797b0d647e97cc811c5b9e827d0b985d87f68f
		
		/* DOMAIN NAMES */
		$D1 = /agegamepay\.\w{2,4}/
		$D2 = /ageofwuxia\.\w{2,4}/
		$D3 = /bugcheck.xigncodeservice\.\w{2,4}/
		$D4 = /byeserver\.\w{2,4}/
		$D5 = /dnsgogle\.\w{2,4}/
		$D6 = /gamewushu\.\w{2,4}/
		$D7 = /gxxservice\.\w{2,4}/
		$D8 = /ibmupdate\.\w{2,4}/
		$D9 = /infestexe\.\w{2,4}/
		$D10 = /kasparsky\.\w{2,4}/
		$D11 = /linux-update\.\w{2,4}/
		$D12 = /macfee\.\w{2,4}/
		$D13 = /micros0ff\.\w{2,4}/
		$D14 = /micros0tf\.\w{2,4}/
		$D15 = /notped\.\w{2,4}/
		$D16 = /operatingbox\.\w{2,4}/
		$D17 = /paniesx\.\w{2,4}/
		$D18 = /serverbye\.\w{2,4}/
		$D19 = /sexyjapan.ddns\.\w{2,4}/
		$D20 = /symanteclabs\.\w{2,4}/
		$D21 = /techniciantext\.\w{2,4}/
		$D22 = /win7update\.\w{2,4}/
		$D23 = /xigncodeservice\.\w{2,4}/
		
		/* EMAILS */
		$E1 = /akbklxp@\d+\.\w{2,4}/
		$E2 = /hackershby@\d+\.\w{2,4}/
		$E3 = hrsimon59@gmail.com
		$E4 = /injuriesa@\w+.com/
		$E5 = /injuriesa@\d+\.\w{2,4}/
		$E6 = /kbklxp@\d+\.\w{2,4}/
		$E7 = /petervc1983@gmail.com/
		$E8 = /ravinder10@(\d+ | \w+).com/
		$E9 = /wolf_zhi@\w+\.com/
		
	condition:
		any of them
 }
 