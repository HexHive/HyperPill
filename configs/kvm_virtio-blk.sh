export MORPHUZZARG=--fuzz-target=generic-fuzz-virtio-blk
# SOURCEPATHS: hw/block/virtio-blk.c
export RANGE_REGEX="virtio-blk"
export LINK_OBJ_REGEX='(text.*hw_virtio)|(text.*virtio-blk)|(text.*pci_msi)'
