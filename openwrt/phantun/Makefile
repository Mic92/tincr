# SPDX-License-Identifier: GPL-2.0-only

include $(TOPDIR)/rules.mk

PKG_NAME:=phantun
PKG_VERSION:=0.8.1
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/dndx/phantun/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=fc435fa909f5410c482bde89d3b03b42a21f4e6314595400cf010c272ef8c023

PKG_MAINTAINER:=Joerg Thalheim <joerg.claude@thalheim.io>
PKG_LICENSE:=MIT Apache-2.0
PKG_LICENSE_FILES:=LICENSE-MIT LICENSE-APACHE

PKG_BUILD_DEPENDS:=rust/host
PKG_BUILD_PARALLEL:=1

MAKE_PATH:=phantun

include $(INCLUDE_DIR)/package.mk
include ../../lang/rust/rust-package.mk

define Package/phantun/Default
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  URL:=https://github.com/dndx/phantun
  DEPENDS:=$(RUST_ARCH_DEPENDS) +kmod-tun
endef

define Package/phantun-client
  $(call Package/phantun/Default)
  TITLE:=Phantun Client - UDP to TCP obfuscation
endef

define Package/phantun-server
  $(call Package/phantun/Default)
  TITLE:=Phantun Server - TCP to UDP deobfuscation
endef

define Package/phantun-client/description
  Phantun Client transforms UDP traffic into obfuscated TCP streams
  that can traverse Layer 3 and Layer 4 (NAPT) firewalls and NATs.
  Deploy the client on the sending side to wrap outgoing UDP in fake TCP.
endef

define Package/phantun-server/description
  Phantun Server receives obfuscated TCP streams from a Phantun Client
  and converts them back into UDP traffic for the upstream service.
  Deploy the server on the receiving side to unwrap fake TCP back to UDP.
endef

define Package/phantun-client/conffiles
/etc/config/phantun-client
endef

define Package/phantun-server/conffiles
/etc/config/phantun-server
endef

define Package/phantun-client/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/bin/client $(1)/usr/bin/phantun-client

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) $(CURDIR)/files/phantun-client.config $(1)/etc/config/phantun-client

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(CURDIR)/files/phantun-client.init $(1)/etc/init.d/phantun-client
endef

define Package/phantun-server/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/bin/server $(1)/usr/bin/phantun-server

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) $(CURDIR)/files/phantun-server.config $(1)/etc/config/phantun-server

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(CURDIR)/files/phantun-server.init $(1)/etc/init.d/phantun-server
endef

$(eval $(call RustBinPackage,phantun-client))
$(eval $(call RustBinPackage,phantun-server))
$(eval $(call BuildPackage,phantun-client))
$(eval $(call BuildPackage,phantun-server))
