export MORPHUZZARG=--fuzz-target=generic-fuzz-nvme
export VIDEZZOTARGET=nvme
export RANGE_REGEX="nvme"
export LINK_OBJ_REGEX='(text.*nvme)|(text.*pci_msi)'
export PCI_ID="1b360010"
# SOURCEPATHS: hw/nvme/
