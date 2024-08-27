export MORPHUZZARG=--fuzz-target=generic-fuzz-virtio-crypto
# SOURCEPATHS: hw/virtio/virtio-crypto.c
export RANGE_REGEX="virtio-crypto"
export LINK_OBJ_REGEX='(text.*hw_virtio)|(text.*virtio-crypto)'
