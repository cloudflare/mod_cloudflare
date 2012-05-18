
all: pkg-deb

.PHONY: pkg-deb
pkg-deb:
	debuild -us -uc


APP_NAME=mod_cloudflare
VERSION=1.0
pkg-rpm:
	mkdir -p ./rpm/RPMS/i386
	mkdir -p ./rpm/SRPMS
	mkdir -p ./rpm/BUILD
	mkdir -p ./rpm/SOURCES
	cp -f ../mod_cloudflare.c ./rpm/SOURCES/
	mkdir -p ./rpm/tmp
	- rm -fr ./rpm/BUILD/$(APP_NAME)-root
	- rm -fr ./rpm/RPMS/$(APP_NAME)-*
	- rm -fr ./rpm/SRPMS/$(APP_NAME)-*
	- rm -fr ./rpm/SOURCES/$(APP_NAME)-*
	rpmbuild --define="_topdir `pwd`/rpm" -ba ../mod_cloudflare.spec

