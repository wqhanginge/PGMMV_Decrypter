#include "minicrypto.h"
#include "cipher_iter.h"


/* initialization functions */

int cipher_iter_type_ready() {
    PyCBCIterType.tp_base = &PyCipherIterType;

    if (PyType_Ready(&PyCipherIterType) < 0) return -1;
    if (PyType_Ready(&PyCBCIterType) < 0) return -1;
    return 0;
}

/* end initialization functions */


/* internal operations of base class CipherIter */

static void _CipherIter_override(PyCipherIterObject* self, cipheriterproc iter_proc) {
    self->iter_proc = iter_proc;
    self->input_iter = NULL;
}

static int _CipherIter_init(PyCipherIterObject* self, PyObject* input_iterable) {
    PyObject* iter = PyObject_GetIter(input_iterable);
    if (!iter) return -1;
    Py_XSETREF(self->input_iter, iter);
    return 0;
}

static void _CipherIter_clear(PyCipherIterObject* self) {
    Py_CLEAR(self->input_iter);
}

static PyObject* _PyCipherIter_iterproc(PyCipherIterObject* self) {
    PyObject* item = PyIter_Next(self->input_iter);
    if (!item) {
        if (!PyErr_Occurred()) PyErr_SetNone(PyExc_StopIteration);
        return NULL;
    }

    Py_buffer block;
    if (PyObject_GetBuffer(item, &block, PyBUF_SIMPLE) < 0) {
        Py_DECREF(item);
        return NULL;
    }
    if (block.len != CIPHER_BLOCKSIZE) {
        PyErr_SetString(PyExc_ValueError, "Illegal block size");
        PyBuffer_Release(&block);
        Py_DECREF(item);
        return NULL;
    }
    Py_DECREF(item);

    uint8_t buffer[2][CIPHER_BLOCKSIZE];
    if (PyBuffer_ToContiguous(buffer[0], &block, CIPHER_BLOCKSIZE, 'C') < 0) {
        PyBuffer_Release(&block);
        return NULL;
    }
    PyBuffer_Release(&block);

    self->iter_proc(self, buffer[1], buffer[0]);
    return PyBytes_FromStringAndSize(buffer[1], CIPHER_BLOCKSIZE);
}

/* end internal operations of base class CipherIter */


/* abstract base class CipherIter */

static PyObject* PyCipherIter_new(PyTypeObject* Py_UNUSED(type), PyObject* Py_UNUSED(args), PyObject* Py_UNUSED(kwds)) {
    return PyErr_Format(PyExc_TypeError, "Abstract class '%s' can not be instantiated", CLASSNAME_CIPHERITER);
}

static PyObject* PyCipherIter_iter(PyCipherIterObject* self) {
    Py_INCREF(self);
    return (PyObject*)self;
}

static PyObject* PyCipherIter_iternext(PyCipherIterObject* Py_UNUSED(self)) {
    PyErr_SetString(PyExc_NotImplementedError, "Abstract method '__next__' is not implemented");
    return NULL;
}


PyTypeObject PyCipherIterType = {
    .ob_base = PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = PYNAME_CONCAT(MODULENAME__MINICRYPTO, CLASSNAME_CIPHERITER),
    .tp_doc = NULL,
    .tp_basicsize = sizeof(PyCipherIterObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_new = PyCipherIter_new,
    .tp_iter = (getiterfunc)PyCipherIter_iter,
    .tp_iternext = (iternextfunc)PyCipherIter_iternext,
};

/* end abstract base class CipherIter */


/* class CBCIter */

struct _PyCBCIterObject {
    PyCipherIterObject base;
    PyCipherObject* cipher;
    uint8_t last_ciphertext_block[CIPHER_BLOCKSIZE];
};


static void _CBCIter_encrypt(PyCBCIterObject* self, uint8_t dst[CIPHER_BLOCKSIZE], uint8_t src[CIPHER_BLOCKSIZE]) {
    minicrypto_xor_bytes(dst, src, self->last_ciphertext_block, CIPHER_BLOCKSIZE);
    self->cipher->encrypt(self->cipher, dst, dst);
    memcpy(self->last_ciphertext_block, dst, CIPHER_BLOCKSIZE);
}

static void _CBCIter_decrypt(PyCBCIterObject* self, uint8_t dst[CIPHER_BLOCKSIZE], uint8_t src[CIPHER_BLOCKSIZE]) {
    self->cipher->decrypt(self->cipher, dst, src);
    minicrypto_xor_bytes(dst, dst, self->last_ciphertext_block, CIPHER_BLOCKSIZE);
    memcpy(self->last_ciphertext_block, src, CIPHER_BLOCKSIZE);
}


static PyObject* PyCBCIter_new(PyTypeObject* type, PyObject* args, PyObject* kwds) {
    static char* kwlist[] = { "cipher", "iv", "input_iterable", "is_decrypt", NULL };

    PyObject* _ignored;
    int is_decrypt = 0;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OOO$p", kwlist, &_ignored, &_ignored, &_ignored, &is_decrypt)) {
        return NULL;
    }

    PyCBCIterObject* self = (PyCBCIterObject*)type->tp_alloc(type, 0);
    if (self) {
        cipheriterproc cbciter_proc = (is_decrypt) ? (cipheriterproc)_CBCIter_decrypt : (cipheriterproc)_CBCIter_encrypt;
        _CipherIter_override((PyCipherIterObject*)self, cbciter_proc);
        self->cipher = NULL;
        memset(self->last_ciphertext_block, 0, CIPHER_BLOCKSIZE);
    }
    return (PyObject*)self;
}

static void PyCBCIter_dealloc(PyCBCIterObject* self) {
    _CipherIter_clear((PyCipherIterObject*)self);
    Py_CLEAR(self->cipher);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static int PyCBCIter_init(PyCBCIterObject* self, PyObject* args, PyObject* kwds, int is_decrypt) {
    static char* kwlist[] = { "cipher", "iv", "input_iterable", "is_decrypt", NULL};

    Py_buffer iv;
    PyObject* cipher, * input_iterable, * _ignored = NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "Oy*O$O", kwlist, &cipher, &iv, &input_iterable, &_ignored)) {
        return -1;
    }
    if (!PyObject_TypeCheck(cipher, &PyCipherType)) {
        PyBuffer_Release(&iv);
        return -1;
    }
    if (iv.len != CIPHER_BLOCKSIZE) {
        PyErr_SetString(PyExc_ValueError, "Illegal IV length");
        PyBuffer_Release(&iv);
        return -1;
    }

    if (_CipherIter_init((PyCipherIterObject*)self, input_iterable) < 0) {
        PyBuffer_Release(&iv);
        return -1;
    }
    if (PyBuffer_ToContiguous(self->last_ciphertext_block, &iv, CIPHER_BLOCKSIZE, 'C') < 0) {
        memset(self->last_ciphertext_block, 0, CIPHER_BLOCKSIZE);
        PyBuffer_Release(&iv);
        return -1;
    }
    PyBuffer_Release(&iv);
    Py_XSETREF(self->cipher, Py_NewRef(cipher));
    return 0;
}

static PyObject* PyCBCIter_iternext(PyCBCIterObject* self) {
    return _PyCipherIter_iterproc((PyCipherIterObject*)self);
}


PyTypeObject PyCBCIterType = {
    .ob_base = PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = PYNAME_CONCAT(MODULENAME__MINICRYPTO, CLASSNAME_CBCITER),
    .tp_doc = NULL,
    .tp_basicsize = sizeof(PyCBCIterObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_new = PyCBCIter_new,
    .tp_dealloc = (destructor)PyCBCIter_dealloc,
    .tp_init = (initproc)PyCBCIter_init,
    .tp_iternext = (iternextfunc)PyCBCIter_iternext,
};

/* end class CBCIter */
