export MORPHUZZARG=--fuzz-target=generic-fuzz-ahci-atapi
export VIDEZZOTARGET=ahci-cd
export RANGE_REGEX="ahci|ide"
export LINK_OBJ_REGEX='(text.*hw_ide)|(text.*dma-helpers)'
# SOURCEPATHS: hw/ide/*
