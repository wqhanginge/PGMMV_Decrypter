#pragma once

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "cipher.h"


/* initialization funcrions */

/*
 * cipher_iter type preparation
 * MUST be called before adding types to module
 */
int cipher_iter_type_ready();


/* abstract base class CipherIter */

#define CLASSNAME_CIPHERITER    "CipherIter"

typedef struct _PyCipherIterObject PyCipherIterObject;
typedef void (*cipheriterproc)(PyCipherIterObject* self, uint8_t dst[CIPHER_BLOCKSIZE], uint8_t src[CIPHER_BLOCKSIZE]);

struct _PyCipherIterObject {
    PyObject_HEAD
    cipheriterproc iter_proc;
    PyObject* input_iter;
};

extern PyTypeObject PyCipherIterType;


/* available iters of block cipher modes of operation */

#define CLASSNAME_CBCITER   "CBCIter"

typedef struct _PyCBCIterObject PyCBCIterObject;
extern PyTypeObject PyCBCIterType;
