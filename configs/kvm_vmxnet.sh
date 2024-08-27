export MORPHUZZARG=--fuzz-target=generic-fuzz-vmxnet3
export VIDEZZOTARGET=vmxnet3
# SOURCEPATHS: hw/net/vmxnet3.c
export RANGE_REGEX="vmxnet|msix.*41"
export PCI_ID="15ad07b0"
export LINK_OBJ_REGEX='(text.*vmxnet)|(text.*pci_pci_host)|(text.*pci_msi)|(text.*hw_net_net)|(text.*\/net_)'
export NOASYNC=1
