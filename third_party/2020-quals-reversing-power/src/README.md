# Build Instructions for ACPI challenge

In order to build the ACPI challenge, from scratch, follow the steps listed below.

1.  First, set up a basic Arch linux installation, using a version of Arch based on the 5.6.14 kernel (it is possible to update this to work with a later kernel, however this is beyond the scope of this README).
    1.  Set up an empty disk image using `dd`. 1.5GiB was used originally.
    1.  Boot into the Arch iso image in qemu, with the generated disk image attached, as a virtio disk.
    1.  Format the disk as MBR. A single root partition is sufficient.
    1.  Follow the Arch installation instructions, from the Arch wiki, until making the image bootable via GRUB. Following past this point (installing network tools, GUI, etc) will not hurt, but is not necessary.
1.  Next, build and install the custom driver.
    1.  Download and unpack a Linux source tree, at version 5.6.14, into directory 5.6.14.
    1.  Configure the kernel with the config in `config`.
    1.  Prepare the kernel, using `make modules_prepare`.
    1.  In the driver/ directory, run `make clean` and `make`.
    1.  In the src/ directory, copy the resulting chck.ko file into a build/ directory, and use `genisoimage` to turn this directory into an iso image.
    1.  Boot into the VM, with the new iso image attached.
    1.  Mount the iso image, and copy chck.ko into `/lib/modules/``uname -a\`/kernel/drivers/char/`.
    1.  Run `depmod 5.6.14-arch1-1`.
1.  Build the ACPI table.
    1.  In the acpi/ directory, run `iasl ssdt.asl`. This should output ssdt.aml.
    1.  Create a directory, called `kernel/firmware/acpi`. Copy `ssdt.aml` into this directory.
    1.  Run `find kernel | cpio -H newc --create > acpi_tables.cpio` to generate the corresponding part of the initrd.
    1.  Copy `acpi_tables.cpio` into a build/ directory, and use `genisoimage` to create an iso image.
    1.  Boot into the VM, with the new iso image attached, and mount the image.
    1.  Cat `acpi_tables.cpio` with the initrd, to create a new initrd: `cat /mnt/acpi_tables.cpio /boot/initrd-linux.img > my_initrd`
    1.  Replace the old initrd. `cp my_initrd /boot/initrd_linux.img`
1.  Set up the login system.
    1.  In the pam/ directory, run `make`. This shall output pam_chck.so.
    1.  Copy this file into a build directory, along with system-auth, and use `genisoimage` to generate an iso image containing both.
    1.  Boot into the VM, with the new iso image attached.
    1.  Mount the iso image, and copy pam_chck.so into `/lib/security/pam_chck.so`.
    1.  Copy system-auth into /etc/pam.d/, overwriting the existing system-auth file.
1.  Boot into the final image, and check that everything has been properly set up. See attachments/run.sh for how to do this.
