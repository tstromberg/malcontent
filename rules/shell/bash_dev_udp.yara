
rule bash_dev_udp : high exfil {
  meta:
    description = "uses /dev/udp for network access (bash)"
    hash_2024_reverse_shells_bash_udp = "3a733928e13662716759fe1f8e560133d1ab21236480fe81ff151b8b69d79147"
  strings:
    $ref = "/dev/udp"
    $posixly_correct = "POSIXLY_CORRECT"
  condition:
    $ref and not $posixly_correct
}
