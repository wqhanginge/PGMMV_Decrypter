#include "minicrypto.h"
#include "cipher_mode.h"


/* initialization functions */

int cipher_mode_type_ready() {
    PyCBCType.tp_base = &PyCipherModeType;

    if (PyType_Ready(&PyCipherModeType) < 0) return -1;
    if (PyType_Ready(&PyCBCType) < 0) return -1;
    return 0;
}

/* end initialization functions */


/* internal operations of base class CipherMode */

static void _CipherMode_override(PyCipherModeObject* self, ciphermodeproc enc_proc, ciphermodeproc dec_proc) {
    self->encrypt = enc_proc;
    self->decrypt = dec_proc;
}

static PyObject* _PyCipherMode_cryptoproc(PyCipherModeObject* self, PyObject* args, PyObject* kwds, ciphermodeproc proc) {
    static char* kwlist[] = { "cipher", "data", NULL };

    uint8_t* data;
    Py_ssize_t dlen;
    PyObject* cipher;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!y#", kwlist, &PyCipherType, &cipher, &data, &dlen)) {
        return NULL;
    }
    if (dlen % CIPHER_BLOCKSIZE) {
        PyErr_Format(PyExc_ValueError, "Length of data must be divisible by %d", CIPHER_BLOCKSIZE);
        return NULL;
    }

    PyObject* result = PyBytes_FromStringAndSize(NULL, dlen);
    if (result) {
        uint8_t* output = PyBytes_AS_STRING(result);
        proc(self, (PyCipherObject*)cipher, output, data, dlen);
    }
    return result;
}

/* end internal operations of base class CipherMode */


/* abstract base class CipherMode */

static PyObject* PyCipherMode_new(PyTypeObject* Py_UNUSED(type), PyObject* Py_UNUSED(args), PyObject* Py_UNUSED(kwds)) {
    return PyErr_Format(PyExc_TypeError, "Abstract class '%s' can not be instantiated", CLASSNAME_CIPHERMODE);
}


static PyObject* PyCipherMode_encrypt(PyCipherModeObject* Py_UNUSED(self), PyObject* Py_UNUSED(args), PyObject* Py_UNUSED(kwds)) {
    PyErr_SetString(PyExc_NotImplementedError, "Abstract method 'encrypt' is not implemented");
    return NULL;
}

static PyObject* PyCipherMode_decrypt(PyCipherModeObject* Py_UNUSED(self), PyObject* Py_UNUSED(args), PyObject* Py_UNUSED(kwds)) {
    PyErr_SetString(PyExc_NotImplementedError, "Abstract method 'decrypt' is not implemented");
    return NULL;
}

static PyMethodDef PyCipherMode_methods[] = {
    { "encrypt", (PyCFunction)PyCipherMode_encrypt, METH_VARARGS | METH_KEYWORDS, NULL },
    { "decrypt", (PyCFunction)PyCipherMode_decrypt, METH_VARARGS | METH_KEYWORDS, NULL },
    { NULL }
};


PyTypeObject PyCipherModeType = {
    .ob_base = PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = PYNAME_CONCAT(MODULENAME_MINICRYPTO, CLASSNAME_CIPHERMODE),
    .tp_doc = NULL,
    .tp_basicsize = sizeof(PyCipherModeObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = PyCipherMode_new,
    .tp_methods = PyCipherMode_methods,
};

/* end abstract base class CipherMode */


/* class CBC */

struct _PyCBCObject {
    PyCipherModeObject base;
    uint8_t iv[CIPHER_BLOCKSIZE];
};


static void _CBC_encrypt(PyCBCObject* self, PyCipherObject* cipher, uint8_t* dst, uint8_t* src, size_t len) {
    uint8_t* last_ciphertext_block = self->iv;
    for (size_t offset = 0; offset < len; offset += CIPHER_BLOCKSIZE) {
        minicrypto_xor_bytes(dst + offset, src + offset, last_ciphertext_block, CIPHER_BLOCKSIZE);
        cipher->encrypt(cipher, dst + offset, dst + offset);
        last_ciphertext_block = dst + offset;
    }
}

static void _CBC_decrypt(PyCBCObject* self, PyCipherObject* cipher, uint8_t* dst, uint8_t* src, size_t len) {
    uint8_t* last_ciphertext_block = self->iv;
    for (size_t offset = 0; offset < len; offset += CIPHER_BLOCKSIZE) {
        cipher->decrypt(cipher, dst + offset, src + offset);
        minicrypto_xor_bytes(dst + offset, dst + offset, last_ciphertext_block, CIPHER_BLOCKSIZE);
        last_ciphertext_block = src + offset;
    }
}


static PyObject* PyCBC_new(PyTypeObject* type, PyObject* Py_UNUSED(args), PyObject* Py_UNUSED(kwds)) {
    PyCBCObject* self = (PyCBCObject*)type->tp_alloc(type, 0);
    if (self) {
        _CipherMode_override((PyCipherModeObject*)self, (ciphermodeproc)_CBC_encrypt, (ciphermodeproc)_CBC_decrypt);
        memset(self->iv, 0, CIPHER_BLOCKSIZE);
    }
    return (PyObject*)self;
}

static int PyCBC_init(PyCBCObject* self, PyObject* args, PyObject* kwds) {
    static char* kwlist[] = { "iv", NULL };

    uint8_t* iv;
    Py_ssize_t ilen;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "y#", kwlist, &iv, &ilen)) {
        return -1;
    }
    if (ilen != CIPHER_BLOCKSIZE) {
        PyErr_SetString(PyExc_ValueError, "Illegal IV length");
        return -1;
    }

    memcpy(self->iv, iv, CIPHER_BLOCKSIZE);
    return 0;
}


static PyObject* PyCBC_iv(PyCBCObject* self, PyObject* Py_UNUSED(args)) {
    return PyBytes_FromStringAndSize(self->iv, CIPHER_BLOCKSIZE);
}

static PyObject* PyCBC_encrypt(PyCBCObject* self, PyObject* args, PyObject* kwds) {
    return _PyCipherMode_cryptoproc((PyCipherModeObject*)self, args, kwds, (ciphermodeproc)_CBC_encrypt);
}

static PyObject* PyCBC_decrypt(PyCBCObject* self, PyObject* args, PyObject* kwds) {
    return _PyCipherMode_cryptoproc((PyCipherModeObject*)self, args, kwds, (ciphermodeproc)_CBC_decrypt);
}

static PyMethodDef PyCBC_methods[] = {
    { "iv", (PyCFunction)PyCBC_iv, METH_NOARGS, NULL },
    { "encrypt", (PyCFunction)PyCBC_encrypt, METH_VARARGS | METH_KEYWORDS, NULL },
    { "decrypt", (PyCFunction)PyCBC_decrypt, METH_VARARGS | METH_KEYWORDS, NULL },
    { NULL }
};


PyTypeObject PyCBCType = {
    .ob_base = PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = PYNAME_CONCAT(MODULENAME_MINICRYPTO, CLASSNAME_CBC),
    .tp_doc = NULL,
    .tp_basicsize = sizeof(PyCBCObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = PyCBC_new,
    .tp_init = (initproc)PyCBC_init,
    .tp_methods = PyCBC_methods,
};

/* end class CBC */
