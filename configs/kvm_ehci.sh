export MORPHUZZARG=--fuzz-target=generic-fuzz-ehci
export VIDEZZOTARGET=ehci
export PCI_ID="8086293a"
export RANGE_REGEX="ich9-ehci"
export LINK_OBJ_REGEX='(text.*hw_usb_hcd-ehci)|(text.*hw_usb_dev-)|(text.*softmmu_memory.c)'
# SOURCEPATHS: hw/usb/hcd-ehci*
