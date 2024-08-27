export MORPHUZZARG=--fuzz-target=generic-fuzz-ohci
# SOURCEPATHS: hw/usb/hcd-ohci.c
export RANGE_REGEX="ohci"
export LINK_OBJ_REGEX='(text.*hw_usb)|(text.*softmmu_memory.c)'
