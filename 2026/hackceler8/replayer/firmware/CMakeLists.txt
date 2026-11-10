cmake_minimum_required(VERSION 3.28.0)

list(APPEND BOARD_ROOT ${CMAKE_CURRENT_SOURCE_DIR})
list(APPEND SNIPPET_ROOT ${CMAKE_CURRENT_SOURCE_DIR})

set(BOARD hackceler8-2026-replayer/rp2350b/m33)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(replayer LANGUAGES C)

target_include_directories(app PRIVATE include)
target_sources(app PRIVATE
  src/main.c
  src/replay_parser.c
  src/status_led.c
  src/trace_storage.c
  src/usb.c
  drivers/replayer/replayer_megadrive_pio.c
)

# src/mpu_regions.c replaces the region layout the SoC comes with, see the file
# for why. Both files define mpu_config, and every Zephyr library is linked
# with --whole-archive, so the SoC's copy has to be taken out of the build
# rather than just left for the linker to not pick.
if(CONFIG_ARM_MPU)
  set(soc_lib soc__raspberrypi__rpi_pico__rp2350)
  if(NOT TARGET ${soc_lib})
    message(FATAL_ERROR "No ${soc_lib} target: has the SoC library been renamed?")
  endif()

  get_target_property(soc_sources ${soc_lib} SOURCES)
  set(soc_mpu_regions ${soc_sources})
  list(FILTER soc_mpu_regions INCLUDE REGEX "(^|/)mpu_regions\\.c$")
  if(NOT soc_mpu_regions)
    message(FATAL_ERROR "No mpu_regions.c in ${soc_lib}: does it still define mpu_config?")
  endif()

  list(REMOVE_ITEM soc_sources ${soc_mpu_regions})
  set_property(TARGET ${soc_lib} PROPERTY SOURCES ${soc_sources})

  target_sources(app PRIVATE src/mpu_regions.c)
endif()

if(CONFIG_XIP AND NOT CONFIG_REPLAYER_DEBUG_IMAGE)
  message(FATAL_ERROR "Production images must be built with CONFIG_XIP=n, otherwise secure boot is pointless.")
endif()

find_program(PICOTOOL picotool)

# Sign the final image.
if(PICOTOOL)
  dt_chosen(flash_node PROPERTY "zephyr,flash")
  dt_reg_addr(flash_addr PATH ${flash_node})
  math(EXPR flash_addr "${flash_addr}" OUTPUT_FORMAT HEXADECIMAL)

  set(signed_elf ${KERNEL_NAME}.signed.elf)
  set(signed_bin ${KERNEL_NAME}.signed.bin)
  set(signed_uf2 ${KERNEL_NAME}.signed.uf2)
  set(signing_key ${CMAKE_CURRENT_SOURCE_DIR}/signing_private.pem)

  if (NOT CONFIG_XIP)
    # Modify the image so that it gets unpacked into the bootrom.
    set(seal_input ${KERNEL_NAME}.dram.elf)
    set(prepare_cmd COMMAND ${CMAKE_OBJCOPY} --change-section-lma '*-0x10000000' ${KERNEL_ELF_NAME} ${seal_input})
    set(comment "Signing DRAM image")
  else()
    # Nothing to do, simply sign the output.
    set(seal_input ${KERNEL_ELF_NAME})
    set(prepare_cmd)
    set(comment "Signing XIP (debug-only) image")
  endif()

  add_custom_command(
    OUTPUT
      ${ZEPHYR_BINARY_DIR}/${signed_elf}
      ${ZEPHYR_BINARY_DIR}/${signed_bin}
      ${ZEPHYR_BINARY_DIR}/${signed_uf2}
    ${prepare_cmd}
    COMMAND ${PICOTOOL} seal --quiet --clear --hash --sign ${seal_input} ${signed_elf} ${signing_key}
    COMMAND ${CMAKE_OBJCOPY} -O binary ${signed_elf} ${signed_bin}
    COMMAND ${PICOTOOL} uf2 convert --quiet ${signed_bin} ${signed_uf2} -o ${flash_addr} --family rp2350-arm-s
    DEPENDS ${logical_target_for_zephyr_elf} ${ZEPHYR_BINARY_DIR}/${KERNEL_ELF_NAME} ${signing_key}
    WORKING_DIRECTORY ${ZEPHYR_BINARY_DIR}
    COMMENT "${comment}"
  )

  add_custom_target(signed_image ALL
    DEPENDS
      ${ZEPHYR_BINARY_DIR}/${signed_elf}
      ${ZEPHYR_BINARY_DIR}/${signed_bin}
      ${ZEPHYR_BINARY_DIR}/${signed_uf2}
  )
else()
  message(WARNING "picotool was not found, so no signed image will be built and replayers with secure boot enabled WILL NOT run this image.")
endif()
