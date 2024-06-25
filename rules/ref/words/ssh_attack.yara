
rule ssh_attack : high {
  meta:
    description = "references an 'SSH Attack'"
    hash_2024_2024_Kaiji_eight_nebraska_autumn_illinois = "38edb3ab96a6aa6c3f4de3590dfb63ca44ddf29d5579ef3b12de326c86145537"
    hash_2023_Chaos_1d36 = "1d36f4bebd21a01c12fde522defee4c6b4d3d574c825ecc20a2b7a8baa122819"
    hash_2023_Chaos_1fc4 = "1fc412b47b736f8405992e3744690b58ec4d611c550a1b4f92f08dfdad5f7a30"
  strings:
    $sshAttack = /[a-zA-Z\-_ ]{0,16}sshAttack[a-zA-Z\-_ ]{0,16}/ fullword
    $ssh_attack = /[a-zA-Z\-_ ]{0,16}ssh_attack[a-zA-Z\-_ ]{0,16}/ fullword
    $attackSSH = /[a-zA-Z\-_ ]{0,16}attackSSH[a-zA-Z\-_ ]{0,16}/ fullword
    $attackSsh = /[a-zA-Z\-_ ]{0,16}attackSsh[a-zA-Z\-_ ]{0,16}/ fullword
    $attack_ssh = /[a-zA-Z\-_ ]{0,16}attack_ssh[a-zA-Z\-_ ]{0,16}/ fullword
    $ssh_boom = /[a-zA-Z\-_ ]{0,16}ssh_boom[a-zA-Z\-_ ]{0,16}/ fullword
  condition:
    any of them
}
