#pragma once

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "cipher.h"


/* initialization funcrions */

/*
 * cipher_mode type preparation
 * MUST be called before adding types to module
 */
int cipher_mode_type_ready();


/* abstract base class CipherMode */

#define CLASSNAME_CIPHERMODE    "CipherMode"

typedef struct _PyCipherModeObject PyCipherModeObject;
typedef void (*ciphermodeproc)(PyCipherModeObject* self, PyCipherObject* cipher, uint8_t* dst, uint8_t* src, size_t len);

struct _PyCipherModeObject {
    PyObject_HEAD
    ciphermodeproc encrypt;
    ciphermodeproc decrypt;
};

extern PyTypeObject PyCipherModeType;


/* available block cipher modes of operation */

#define CLASSNAME_CBC   "CBC"

typedef struct _PyCBCObject PyCBCObject;
extern PyTypeObject PyCBCType;
