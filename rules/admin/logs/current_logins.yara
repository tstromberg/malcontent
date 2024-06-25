
rule login_records : medium {
  meta:
    description = "accesses current logins"
    hash_2023_usr_adxintrin_b = "a51a4ddcd092b102af94139252c898d7c1c48f322bae181bd99499a79c12c500"
    hash_2023_Linux_Malware_Samples_0638 = "063830221431f8136766f2d740df6419c8cd2f73b10e07fa30067df506592210"
    hash_2023_Linux_Malware_Samples_1f94 = "1f94aa7ad1803a08dab3442046c9d96fc3d19d62189f541b07ed732e0d62bf05"
  strings:
    $f_wtmp = "/var/log/wtmp"
    $not_cshell = "_PATH_CSHELL" fullword
    $not_rwho = "_PATH_RWHODIR" fullword
  condition:
    any of ($f*) and none of ($not*)
}
