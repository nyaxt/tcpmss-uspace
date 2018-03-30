# tcpmss-uspace.c

tcpmss-uspace is TCPMSS iptables target equivalent in userspace. Now that nftables have evolved to support clamping natively in Linux kernel 4.14, the original use case is obsolete.
See [the article in nftables wiki](https://wiki.nftables.org/wiki-nftables/index.php/Mangle_TCP_options) for more details.

## Using tcpmss-uspace w/ nftables
tcpmss-uspace was originally made as a workaround to clamp MSS on nftables env.

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

## License
tcpmss-uspace is provided under GPLv2 to match libnetfilter_queue.
