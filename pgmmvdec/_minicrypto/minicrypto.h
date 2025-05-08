#pragma once

#include <stdint.h>


#define PYNAME_CONCAT(m,c)          m "." c
#define MODULENAME__MINICRYPTO      "_minicrypto"


/* general functions */

void minicrypto_xor_bytes(uint8_t* ret, uint8_t* ba, uint8_t* bb, size_t len);
