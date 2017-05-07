# tcpmss-uspace.c

tcpmss-uspace is TCPMSS iptables target equivalent in userspace.

## Using tcpmss-uspace w/ nftables
tcpmss-uspace can be used to clamp MSS on nftables env, where [xt TCPMSS is not yet supported (as of May 2017).](https://wiki.nftables.org/wiki-nftables/index.php/Supported_features_compared_to_xtables#tcpmss).

### Sample nftables.conf:
```
table ip mangle {
  chain postrouting {
    type filter hook postrouting priority 100;
    oifname "ppp0" tcp flags & (syn | rst) == syn counter queue num 0  
  }
}
```

then, run tcpmss-uspace as root:
```
sudo ./tcpmss-uspace 0 1414
```
