export MORPHUZZARG=--fuzz-target=generic-fuzz-xhci
export VIDEZZOTARGET=xhci
# SOURCEPATHS: hw/usb/hcd-xhci.c 
# hw/usb/dev-*
export PCI_ID="1b36000d"
export RANGE_REGEX="xhci|msix.*xhci"
export LINK_OBJ_REGEX='(text.*hw_usb_hcd-xhci)|(text.*hw_usb_dev-)|(text.*softmmu_memory.c)|(text.*hw_scsi)|(text.*pci_msi)'
