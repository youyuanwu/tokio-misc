# vcpkg_list(APPEND CONFIGURE_OPTIONS enable-ktls)
vcpkg_configure_make(
  SOURCE_PATH "${SOURCE_PATH}"
  CONFIGURE_OPTIONS
    --prefix=${CURRENT_PACKAGES_DIR}
    --openssldir=${CURRENT_PACKAGES_DIR}/etc/ssl
    enable-ktls
)