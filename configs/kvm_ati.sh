export MORPHUZZARG=--fuzz-target=generic-fuzz-ati-display
# SOURCEPATHS: hw/display/ati.c
export RANGE_REGEX="ati.mmregs|vga"
export LINK_OBJ_REGEX='(text.*hw_display_ati)'
