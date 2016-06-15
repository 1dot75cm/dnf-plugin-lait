SET (ARCHS "x86_64" "i386")
SET (RELEASES "22" "23" "24")

foreach (ARCH ${ARCHS})
foreach (RELEASE ${RELEASES})
CONFIGURE_FILE (
    "${PROJECT_SOURCE_DIR}/mock/mock.cfg.template"
    "${PROJECT_BINARY_DIR}/mock/fedora-${RELEASE}-${ARCH}-lait.cfg" @ONLY
    )
INSTALL (FILES "${PROJECT_BINARY_DIR}/mock/fedora-${RELEASE}-${ARCH}-lait.cfg" DESTINATION "${SYSCONFDIR}/mock")
endforeach()
endforeach()
#INSTALL (DIRECTORY "${PROJECT_BINARY_DIR}/mock/" DESTINATION "${SYSCONFDIR}/mock" FILES_MATCHING PATTERN "*.cfg")
