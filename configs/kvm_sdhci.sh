export MORPHUZZARG=--fuzz-target=generic-fuzz-sdhci-v3
export VIDEZZOTARGET=sdhci-v3
# SOURCEPATHS: hw/sd/sdhci.c
export PCI_ID="1b360007"
export RANGE_REGEX="sdhci|msix.*29"
export LINK_OBJ_REGEX='(text.*hw_sd_)'
