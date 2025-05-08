#pragma once

#define PY_SSIZE_T_CLEAN
#include <Python.h>


#define CIPHER_BLOCKSIZE    16      /* MUST NOT change this */


/* initialization funcrions */

/*
 * cipher type preparation
 * MUST be called before adding types to module
 */
int cipher_type_ready();

/*
 * cipher initialization function
 * MUST be called during the module initialization process
 */
void cipher_initialize();


/* abstract base class Cipher */

#define CLASSNAME_CIPHER    "Cipher"

typedef struct _PyCipherObject PyCipherObject;
typedef void (*cipherproc)(PyCipherObject* self, uint8_t dst[CIPHER_BLOCKSIZE], uint8_t src[CIPHER_BLOCKSIZE]);

struct _PyCipherObject {
    PyObject_HEAD
    cipherproc encrypt;
    cipherproc decrypt;
};

extern PyTypeObject PyCipherType;


/* available ciphers */

#define CLASSNAME_TWOFISH   "Twofish"
#define CLASSNAME_WEAKFISH  "Weakfish"

typedef struct _PyTwofishObject PyTwofishObject;
extern PyTypeObject PyTwofishType;

typedef struct _PyWeakfishObject PyWeakfishObject;
extern PyTypeObject PyWeakfishType;
