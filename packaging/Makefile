
all: 

.PHONY: pkg-deb-system-prep
pkg-deb-system-prep:
	apt-get install devscripts debhelper apache2-dev

.PHONY: pkg-deb
pkg-deb:
	debuild -us -uc


APP_NAME=mod_cloudflare
VERSION=1.0

.PHONY: pkg-rpm-system-prep
pkg-rpm-system-prep:
	yum install -y rpm-build httpd-devel

.PHONY: pkg-rpm-suse-system-prep
pkg-rpm-suse-system-prep:
	zypper install -y rpm-build apache2-devel

.PHONY:pkg-rpm-prep
pkg-rpm-prep:
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

pkg-rpm: pkg-rpm-prep
	rpmbuild --define="_topdir `pwd`/rpm" -ba ./rpm/mod_cloudflare.spec

pkg-rpm-suse: pkg-rpm-prep
	rpmbuild --define="_topdir `pwd`/rpm" -ba ./rpm/mod_cloudflare.suse.spec

.PHONY: archive-src
archive-src:
	git archive --prefix=mod_cloudflare/ --format=tar HEAD `pwd`/../ -o  mod_cloudflare.`git log -n1 --pretty='%h' HEAD`.src.tar
