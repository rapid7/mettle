LUA_VERSION=5.3.4

$(BUILD)/lua/Makefile: build/tools
	@echo "Unpacking lua for $(TARGET)"
	@mkdir -p $(BUILD)
	@cd $(BUILD); \
		rm -rf $(BUILD)/lua; \
		$(TAR) zxf $(DEPS)/lua-$(LUA_VERSION).tar.gz; \
		mv lua-$(LUA_VERSION) lua

$(BUILD)/lib/liblua.a: $(BUILD)/lua/Makefile
	@echo "Building lua for $(TARGET) $(BUILD)"
	@cd $(BUILD)/lua; \
		$(MAKE) generic $(LOGBUILD); \
		$(MAKE_INSTALL) INSTALL_TOP=$(BUILD) $(LOGBUILD)

lua: $(BUILD)/lib/liblua.a
