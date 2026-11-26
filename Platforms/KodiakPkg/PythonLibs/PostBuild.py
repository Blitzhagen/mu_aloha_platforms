import logging
import gzip
import os
import sys
import mkbootimg

def makeAndroidImage(outputbin_dir, output_dir, root_dir, device_name, dtb_name) :
    bootpayload_path = os.path.join(output_dir, 'bootpayload.bin')
    output_path = os.path.join(output_dir, device_name + '.img')
    fd_path = os.path.join(outputbin_dir, 'FV', 'SM7325_EFI.fd')
    bootshim_path = os.path.join(root_dir, 'BootShim', 'BootShim.bin')
    dtb_path = os.path.join(root_dir, "Platforms", "KodiakPkg", "Device", device_name, 'DeviceTreeBlob', 'Android', 'android-' + dtb_name)

    logging.info("Generating bootpayload.bin")

    '''
      Payload:
        | BootShim.bin | SMxxxx_EFI.fd |
    '''
    with open(bootpayload_path, 'wb') as f:
        logging.info("Writing UEFI...")
        data = bytes()

        with open(bootshim_path, 'rb') as bootshim_file:
            data += bootshim_file.read()

        with open(fd_path, 'rb') as fd:
            data += fd.read()
            data = gzip.compress(data, 9)
            f.write(data)

        logging.info("Writing DTB...")
        with open(dtb_path, 'rb') as dtb:
            data = dtb.read()
            f.write(data)


    logging.info("Writing " + device_name + '.img')

    mkbootimg.main([
        "--kernel", bootpayload_path,
        "-o", output_path,
        "--ramdisk", "./ImageResources/emptyramdisk",
        "--pagesize", "4096",
        "--header_version", "0",
        "--cmdline", "",
        "--base", "0x0",
        "--os_version", "11.0.0",
        "--os_patch_level", "2023-04-01"
    ])

    # samsung-gts7xllite flashing expects the boot image to occupy at least
    # the stock 734 4KiB pages (3006464 bytes).  mkbootimg already page-aligns
    # its output, but a smaller compressed payload can legitimately produce
    # 733 pages; pad reproducibly instead of fixing the image by hand.
    if device_name == "samsung-gts7xllite":
        min_image_size = 734 * 4096
        image_size = os.path.getsize(output_path)
        if image_size < min_image_size:
            padding = min_image_size - image_size
            logging.info("Padding " + device_name + ".img by " + str(padding) + " bytes to " + str(min_image_size))
            with open(output_path, 'ab') as output_image:
                output_image.write(bytes(padding))
