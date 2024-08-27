export MORPHUZZARG=--fuzz-target=generic-fuzz-virtio-scsi
export VIDEZZOTARGET=virtio-scsi
# SOURCEPATHS: hw/scsi/virtio-scsi.c
export PCI_ID="1af41004"
export RANGE_REGEX="virtio-scsi"
export LINK_OBJ_REGEX='(text.*hw_virtio)|(text.*virtio-scsi)|(text.*pci_msi)'
