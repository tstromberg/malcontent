
rule iptables_delete : high {
  meta:
    syscall = "posix_spawn"
    pledge = "exec"
    description = "Deletes rules from a iptables chain"
    hash_2023_Linux_Malware_Samples_0638 = "063830221431f8136766f2d740df6419c8cd2f73b10e07fa30067df506592210"
    hash_2023_Linux_Malware_Samples_1f94 = "1f94aa7ad1803a08dab3442046c9d96fc3d19d62189f541b07ed732e0d62bf05"
    hash_2023_Linux_Malware_Samples_31e8 = "31e87fa24f5d3648f8db7caca8dfb15b815add4dfc0fabe5db81d131882b4d38"
  strings:
    $ref = /iptables [\-\w% ]{0,8} -D[\-\w% ]{0,32}/
  condition:
    any of them
}
