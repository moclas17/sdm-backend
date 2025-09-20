import binascii

# used for derivation of per-tag keys
DERIVE_MODE = "legacy"
MASTER_KEY = binascii.unhexlify("00000000000000000000000000000000")

# for plaintext mirroring
UID_PARAM = "uid"
CTR_PARAM = "ctr"
SDMMAC_PARAM = "cmac"

# accept only SDM using LRP, disallow usage of AES
REQUIRE_LRP = False
