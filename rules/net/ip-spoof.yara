
rule ip_spoof : high {
  meta:
    pledge = "inet"
    description = "spoof IP addresses"
    hash_2024_2024_Kaiji_eight_nebraska_autumn_illinois = "38edb3ab96a6aa6c3f4de3590dfb63ca44ddf29d5579ef3b12de326c86145537"
    hash_2023_Chaos_1d36 = "1d36f4bebd21a01c12fde522defee4c6b4d3d574c825ecc20a2b7a8baa122819"
    hash_2023_Chaos_1fc4 = "1fc412b47b736f8405992e3744690b58ec4d611c550a1b4f92f08dfdad5f7a30"
  strings:
    $ip_spoof = "ipspoof" fullword
  condition:
    any of them
}
