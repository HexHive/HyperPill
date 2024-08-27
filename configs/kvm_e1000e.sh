export MORPHUZZARG=--fuzz-target=generic-fuzz-e1000e
export VIDEZZOTARGET=e1000e
export RANGE_REGEX="e1000e|msix.*35"
export LINK_OBJ_REGEX='(text.*hw_net_e1000)|(text.*hw_net_net)|(text.*\/net_)|(text.*pci_msi)'
export PCI_ID="808610d3"
# SOURCEPATHS: hw/net/e1000*
