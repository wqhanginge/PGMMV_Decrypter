#include "minicrypto.h"
#include "cipher_iter.h"


/* initialization functions */

int cipher_iter_type_ready() {
    PyCBCEncIterType.tp_base = &PyCipherIterType;
    PyCBCDecIterType.tp_base = &PyCipherIterType;

    if (PyType_Ready(&PyCipherIterType) < 0) return -1;
    if (PyType_Ready(&PyCBCEncIterType) < 0) return -1;
    if (PyType_Ready(&PyCBCDecIterType) < 0) return -1;
    return 0;
}

/* end initialization functions */


/* internal operations of base class CipherIter */

static void _CipherIter_override(PyCipherIterObject* self, cipheriterproc crypto) {
    self->crypto = crypto;
}

static PyObject* _PyCipherIter_iterproc(PyCipherIterObject* self, PyObject* input) {
    uint8_t* block;
    Py_ssize_t blen;
    if (PyBytes_AsStringAndSize(input, &block, &blen) < 0) {
        return NULL;
    }
    if (blen != CIPHER_BLOCKSIZE) {
        PyErr_SetString(PyExc_ValueError, "Illegal block size");
        return NULL;
    }

    uint8_t output[CIPHER_BLOCKSIZE];
    self->crypto(self, output, block);
    return PyBytes_FromStringAndSize(output, CIPHER_BLOCKSIZE);
}

/* end internal operations of base class CipherIter */


/* abstract base class CipherIter */

static PyObject* PyCipherIter_new(PyTypeObject* Py_UNUSED(type), PyObject* Py_UNUSED(args), PyObject* Py_UNUSED(kwds)) {
    return PyErr_Format(PyExc_TypeError, "Abstract class '%s' can not be instantiated", CLASSNAME_CIPHERITER);
}

static PyObject* PyCipherIter_iter(PyCipherIterObject* self) {
    return Py_NewRef(self);
}

static PyObject* PyCipherIter_iternext(PyCipherIterObject* Py_UNUSED(self)) {
    PyErr_SetString(PyExc_NotImplementedError, "Abstract method '__next__' is not implemented");
    return NULL;
}


PyTypeObject PyCipherIterType = {
    .ob_base = PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = PYNAME_CONCAT(MODULENAME_MINICRYPTO, CLASSNAME_CIPHERITER),
    .tp_doc = NULL,
    .tp_basicsize = sizeof(PyCipherIterObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = PyCipherIter_new,
    .tp_iter = (getiterfunc)PyCipherIter_iter,
    .tp_iternext = (iternextfunc)PyCipherIter_iternext,
};

/* end abstract base class CipherIter */


/* internal class CBCIter */

typedef struct _PyCBCIterObject {
    PyCipherIterObject base;
    PyCipherObject* cipher;
    PyObject* input_iter;
    uint8_t last_ciphertext_block[CIPHER_BLOCKSIZE];
} _PyCBCIterObject;


static void _CBCIter_encrypt(_PyCBCIterObject* self, uint8_t dst[CIPHER_BLOCKSIZE], uint8_t src[CIPHER_BLOCKSIZE]) {
    minicrypto_xor_bytes(dst, src, self->last_ciphertext_block, CIPHER_BLOCKSIZE);
    self->cipher->encrypt(self->cipher, dst, dst);
    memcpy(self->last_ciphertext_block, dst, CIPHER_BLOCKSIZE);
}

static void _CBCIter_decrypt(_PyCBCIterObject* self, uint8_t dst[CIPHER_BLOCKSIZE], uint8_t src[CIPHER_BLOCKSIZE]) {
    self->cipher->decrypt(self->cipher, dst, src);
    minicrypto_xor_bytes(dst, dst, self->last_ciphertext_block, CIPHER_BLOCKSIZE);
    memcpy(self->last_ciphertext_block, src, CIPHER_BLOCKSIZE);
}


static PyObject* _PyCBCIter_new(PyTypeObject* type, cipheriterproc crypto) {
    _PyCBCIterObject* self = (_PyCBCIterObject*)type->tp_alloc(type, 0);
    if (self) {
        _CipherIter_override((PyCipherIterObject*)self, crypto);
        self->cipher = NULL;
        self->input_iter = NULL;
        memset(self->last_ciphertext_block, 0, CIPHER_BLOCKSIZE);
    }
    return (PyObject*)self;
}

static void _PyCBCIter_dealloc(_PyCBCIterObject* self) {
    Py_CLEAR(self->cipher);
    Py_CLEAR(self->input_iter);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static int _PyCBCIter_init(_PyCBCIterObject* self, PyObject* args, PyObject* kwds) {
    static char* kwlist[] = { "cipher", "iv", "input_iterable", NULL };

    uint8_t* iv;
    Py_ssize_t ilen;
    PyObject* cipher, * input_iterable;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!y#O", kwlist, &PyCipherType, &cipher, &iv, &ilen, &input_iterable)) {
        return -1;
    }
    if (ilen != CIPHER_BLOCKSIZE) {
        PyErr_SetString(PyExc_ValueError, "Illegal IV length");
        return -1;
    }

    PyObject* input_iter = PyObject_GetIter(input_iterable);
    if (!input_iter) {
        return -1;
    }

    Py_XSETREF(self->cipher, Py_NewRef(cipher));
    Py_XSETREF(self->input_iter, input_iter);
    memcpy(self->last_ciphertext_block, iv, CIPHER_BLOCKSIZE);
    return 0;
}

static PyObject* _PyCBCIter_iternext(_PyCBCIterObject* self) {
    PyObject* item = PyIter_Next(self->input_iter);
    if (!item) {
        if (!PyErr_Occurred()) PyErr_SetNone(PyExc_StopIteration);
        return NULL;
    }

    PyObject* result = _PyCipherIter_iterproc((PyCipherIterObject*)self, item);
    Py_DECREF(item);
    return result;
}

/* end internal class CBCIter */


/* class CBCEncIter */

static PyObject* PyCBCEncIter_new(PyTypeObject* type, PyObject* Py_UNUSED(args), PyObject* Py_UNUSED(kwds)) {
    return _PyCBCIter_new(type, (cipheriterproc)_CBCIter_encrypt);
}


PyTypeObject PyCBCEncIterType = {
    .ob_base = PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = PYNAME_CONCAT(MODULENAME_MINICRYPTO, CLASSNAME_CBCENCITER),
    .tp_doc = NULL,
    .tp_basicsize = sizeof(PyCBCEncIterObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = PyCBCEncIter_new,
    .tp_dealloc = (destructor)_PyCBCIter_dealloc,
    .tp_init = (initproc)_PyCBCIter_init,
    .tp_iternext = (iternextfunc)_PyCBCIter_iternext,
};

/* end class CBCEncIter */


/* class CBCDecIter */

static PyObject* PyCBCDecIter_new(PyTypeObject* type, PyObject* Py_UNUSED(args), PyObject* Py_UNUSED(kwds)) {
    return _PyCBCIter_new(type, (cipheriterproc)_CBCIter_decrypt);
}


PyTypeObject PyCBCDecIterType = {
    .ob_base = PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = PYNAME_CONCAT(MODULENAME_MINICRYPTO, CLASSNAME_CBCDECITER),
    .tp_doc = NULL,
    .tp_basicsize = sizeof(PyCBCDecIterObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = PyCBCDecIter_new,
    .tp_dealloc = (destructor)_PyCBCIter_dealloc,
    .tp_init = (initproc)_PyCBCIter_init,
    .tp_iternext = (iternextfunc)_PyCBCIter_iternext,
};

/* end class CBCDecIter */
