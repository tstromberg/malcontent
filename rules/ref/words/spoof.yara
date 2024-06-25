
rule spoof : medium {
  meta:
    description = "references spoofing"
    hash_2024_2024_Kaiji_eight_nebraska_autumn_illinois = "38edb3ab96a6aa6c3f4de3590dfb63ca44ddf29d5579ef3b12de326c86145537"
    hash_2024_numpy_misc_util = "8980b131230f9f064099a320180ec2143f9f4e831728042c8f2cfba3d33f38b7"
    hash_2023_Downloads_21ca = "21ca44d382102e0ae33d02f499a5aa2a01e0749be956cbd417aae64085f28368"
  strings:
    $ref = /[a-zA-Z\-_ ]{0,16}spoof[a-zA-Z\-_ ]{0,16}/ fullword
    $ref2 = /[a-zA-Z\-_ ]{0,16}spoof[a-zA-Z\-_ ]{0,16}/ fullword
  condition:
    any of them
}
