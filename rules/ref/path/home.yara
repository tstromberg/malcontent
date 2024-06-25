
rule home_path : medium {
  meta:
    description = "references path within /home"
    hash_2024_synthetic_cnc_dns_over_https = "4f07f1c783affdde5ac4eb029e10c1a13d69d8b04f14897277f226b0f342013c"
    hash_2024_2021_DiscordSafety_setup = "7dfa21dda6b275952ee8410a19b0f38e1071588be5894cf052329ca106eae6e1"
    hash_2024_numpy_misc_util = "8980b131230f9f064099a320180ec2143f9f4e831728042c8f2cfba3d33f38b7"
  strings:
    $home = /\/home\/[%\w\.\-\/]{0,64}/
    $not_build = "/home/build"
    $not_runner = "/home/runner"
  condition:
    $home and none of ($not*)
}
