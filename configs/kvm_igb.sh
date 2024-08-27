export MORPHUZZARG=--fuzz-target=generic-fuzz-igb
export RANGE_REGEX="igb|msix.*36"
export LINK_OBJ_REGEX='(text.*hw_net_igb)|(text.*hw_net_e1000)|(text.*pci_msi)|(text.*hw_net_net)|(text.*\/net_)'
export PCI_ID="808610c9"
# SOURCEPATHS: hw/net/igb*
