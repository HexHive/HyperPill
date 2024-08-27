export MORPHUZZARG=--fuzz-target=generic-fuzz-pcnet
# SOURCEPATHS: hw/net/pcnet.c
export RANGE_REGEX="pcnet"
export LINK_OBJ_REGEX='(text.*hw_net_pcnet)'
