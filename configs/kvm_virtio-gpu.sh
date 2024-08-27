export MORPHUZZARG=--fuzz-target=generic-fuzz-virtio-gpu
export VIDEZZOTARGET=virtio-gpu
# SOURCEPATHS: hw/display/virtio-gpu.c
export PCI_ID="1af41050"
export RANGE_REGEX="virtio-gpu|vga|msix.*44"
export LINK_OBJ_REGEX='(text.*hw_virtio)|(text.*hw_display_virtio-)|(text.*pci_msi)'
