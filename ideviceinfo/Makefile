all:
	gcc ideviceinfo.c common/utils.c -I/usr/include -L/usr/lib/x86_64-linux-gnu -lssl -lcrypto -lplist -lplist++ -limobiledevice -o ideviceinfo
	gcc ideviceinfo2.c common/utils.c -I/usr/include -L/usr/lib/x86_64-linux-gnu -lssl -lcrypto -lplist -lplist++ -limobiledevice -o ideviceinfo2

clean:
	rm -f ideviceinfo
	rm -f ideviceinfo2
