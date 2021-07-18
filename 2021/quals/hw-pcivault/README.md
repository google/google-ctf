# PCIVault challenge

The challenge consists out of two VMs and an emulated PCI device (`emulator`
binary). The contestants will get access to the serial port of one of the VMs
and need to exploit bugs in the PCI device to get code execution there and
finally on the secondary flag-VM which is also connected to the device.
