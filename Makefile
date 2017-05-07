tcpmss-uspace: tcpmss-uspace.c
	clang -g -o tcpmss-uspace -lmnl -lnetfilter_queue tcpmss-uspace.c
