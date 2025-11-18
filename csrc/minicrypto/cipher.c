#include "minicrypto.h"
#include "cipher.h"
#include "cipher/twofish.h"
#include "cipher/weakfish.h"


#define TWOFISH_MINKEYLEN   0
#define TWOFISH_MAXKEYLEN   32


/* general fatal function */

void cipher_fatal(const char* msg) {
    Py_FatalError(msg);
}

/* end general fatal function */


/* initialization functions */

int cipher_type_ready() {
    PyIdentityType.tp_base = &PyCipherType;
    PyTwofishType.tp_base = &PyCipherType;
    PyWeakfishType.tp_base = &PyCipherType;

    if (PyType_Ready(&PyCipherType) < 0) return -1;
    if (PyType_Ready(&PyIdentityType) < 0) return -1;
    if (PyType_Ready(&PyTwofishType) < 0) return -1;
    if (PyType_Ready(&PyWeakfishType) < 0) return -1;
    return 0;
}

void cipher_initialize() {
    Twofish_initialise();
    Weakfish_selftest();
}

/* end initialization functions */


/* internal operations of base class Cipher */

static void _Cipher_override(PyCipherObject* self, cipherproc enc_proc, cipherproc dec_proc) {
    self->encrypt = enc_proc;
    self->decrypt = dec_proc;
}

static PyObject* _PyCipher_cryptoproc(PyCipherObject* self, PyObject* args, PyObject* kwds, cipherproc proc) {
    static char* kwlist[] = { "block", NULL };

    uint8_t* block;
    Py_ssize_t blen;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "y#", kwlist, &block, &blen)) {
        return NULL;
    }
    if (blen != CIPHER_BLOCKSIZE) {
        PyErr_SetString(PyExc_ValueError, "Illegal block size");
        return NULL;
    }

    uint8_t output[CIPHER_BLOCKSIZE];
    proc(self, output, block);
    return PyBytes_FromStringAndSize(output, CIPHER_BLOCKSIZE);
}

/* end internal operations of base class Cipher */


/* abstract base class Cipher */

static PyObject* PyCipher_new(PyTypeObject* Py_UNUSED(type), PyObject* Py_UNUSED(args), PyObject* Py_UNUSED(kwds)) {
    return PyErr_Format(PyExc_TypeError, "Abstract class '%s' can not be instantiated", CLASSNAME_CIPHER);
}


static PyObject* PyCipher_encrypt(PyCipherObject* Py_UNUSED(self), PyObject* Py_UNUSED(args), PyObject* Py_UNUSED(kwds)) {
    PyErr_SetString(PyExc_NotImplementedError, "Abstract method 'encrypt' is not implemented");
    return NULL;
}

static PyObject* PyCipher_decrypt(PyCipherObject* Py_UNUSED(self), PyObject* Py_UNUSED(args), PyObject* Py_UNUSED(kwds)) {
    PyErr_SetString(PyExc_NotImplementedError, "Abstract method 'decrypt' is not implemented");
    return NULL;
}

static PyMethodDef PyCipher_methods[] = {
    { "encrypt", (PyCFunction)PyCipher_encrypt, METH_VARARGS | METH_KEYWORDS, NULL },
    { "decrypt", (PyCFunction)PyCipher_decrypt, METH_VARARGS | METH_KEYWORDS, NULL },
    { NULL }
};


PyTypeObject PyCipherType = {
    .ob_base = PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = PYNAME_CONCAT(MODULENAME__MINICRYPTO, CLASSNAME_CIPHER),
    .tp_doc = NULL,
    .tp_basicsize = sizeof(PyCipherObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = PyCipher_new,
    .tp_methods = PyCipher_methods,
};

/* end abstract base class Cipher */


/* class Identity */

struct _PyIdentityObject {
    PyCipherObject base;
};


static void _Identity_crypto(PyIdentityObject* Py_UNUSED(self), uint8_t dst[CIPHER_BLOCKSIZE], uint8_t src[CIPHER_BLOCKSIZE]) {
    memcpy(dst, src, CIPHER_BLOCKSIZE);
}


static PyObject* PyIdentity_new(PyTypeObject* type, PyObject* Py_UNUSED(args), PyObject* Py_UNUSED(kwds)) {
    PyIdentityObject* self = (PyIdentityObject*)type->tp_alloc(type, 0);
    if (self) {
        _Cipher_override((PyCipherObject*)self, (cipherproc)_Identity_crypto, (cipherproc)_Identity_crypto);
    }
    return (PyObject*)self;
}

static int PyIdentity_init(PyIdentityObject* Py_UNUSED(self), PyObject* args, PyObject* kwds) {
    static char* kwlist[] = { NULL };

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "", kwlist)) {
        return -1;
    }
    return 0;
}


static PyObject* PyIdentity_encrypt(PyIdentityObject* self, PyObject* args, PyObject* kwds) {
    return _PyCipher_cryptoproc((PyCipherObject*)self, args, kwds, (cipherproc)_Identity_crypto);
}

static PyObject* PyIdentity_decrypt(PyIdentityObject* self, PyObject* args, PyObject* kwds) {
    return _PyCipher_cryptoproc((PyCipherObject*)self, args, kwds, (cipherproc)_Identity_crypto);
}

static PyMethodDef PyIdentity_methods[] = {
    { "encrypt", (PyCFunction)PyIdentity_encrypt, METH_VARARGS | METH_KEYWORDS, NULL },
    { "decrypt", (PyCFunction)PyIdentity_decrypt, METH_VARARGS | METH_KEYWORDS, NULL },
    { NULL }
};


PyTypeObject PyIdentityType = {
    .ob_base = PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = PYNAME_CONCAT(MODULENAME__MINICRYPTO, CLASSNAME_IDENTITY),
    .tp_doc = NULL,
    .tp_basicsize = sizeof(PyIdentityObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = PyIdentity_new,
    .tp_init = (initproc)PyIdentity_init,
    .tp_methods = PyIdentity_methods,
};

/* end class Identity */


/* class Twofish */

struct _PyTwofishObject {
    PyCipherObject base;
    size_t key_len;
    uint8_t key[TWOFISH_MAXKEYLEN];
    Twofish_key internal_key;
};


static void _Twofish_encrypt(PyTwofishObject* self, uint8_t dst[CIPHER_BLOCKSIZE], uint8_t src[CIPHER_BLOCKSIZE]) {
    Twofish_encrypt(&self->internal_key, src, dst);
}

static void _Twofish_decrypt(PyTwofishObject* self, uint8_t dst[CIPHER_BLOCKSIZE], uint8_t src[CIPHER_BLOCKSIZE]) {
    Twofish_decrypt(&self->internal_key, src, dst);
}


static PyObject* PyTwofish_new(PyTypeObject* type, PyObject* Py_UNUSED(args), PyObject* Py_UNUSED(kwds)) {
    PyTwofishObject* self = (PyTwofishObject*)type->tp_alloc(type, 0);
    if (self) {
        _Cipher_override((PyCipherObject*)self, (cipherproc)_Twofish_encrypt, (cipherproc)_Twofish_decrypt);
        self->key_len = 0;
        memset(self->key, 0, sizeof(self->key));
        memset(&self->internal_key, 0, sizeof(self->internal_key));
    }
    return (PyObject*)self;
}

static int PyTwofish_init(PyTwofishObject* self, PyObject* args, PyObject* kwds) {
    static char* kwlist[] = { "key", NULL };

    uint8_t* key;
    Py_ssize_t klen;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "y#", kwlist, &key, &klen)) {
        return -1;
    }
    if (klen < TWOFISH_MINKEYLEN || klen > TWOFISH_MAXKEYLEN) {
        PyErr_SetString(PyExc_ValueError, "Illegal key length");
        return -1;
    }

    self->key_len = klen;
    memcpy(self->key, key, klen);
    Twofish_prepare_key(self->key, (int)self->key_len, &self->internal_key);
    return 0;
}


static PyObject* PyTwofish_key(PyTwofishObject* self, PyObject* Py_UNUSED(args)) {
    return PyBytes_FromStringAndSize(self->key, self->key_len);
}

static PyObject* PyTwofish_encrypt(PyTwofishObject* self, PyObject* args, PyObject* kwds) {
    return _PyCipher_cryptoproc((PyCipherObject*)self, args, kwds, (cipherproc)_Twofish_encrypt);
}

static PyObject* PyTwofish_decrypt(PyTwofishObject* self, PyObject* args, PyObject* kwds) {
    return _PyCipher_cryptoproc((PyCipherObject*)self, args, kwds, (cipherproc)_Twofish_decrypt);
}

static PyMethodDef PyTwofish_methods[] = {
    { "key", (PyCFunction)PyTwofish_key, METH_NOARGS, NULL },
    { "encrypt", (PyCFunction)PyTwofish_encrypt, METH_VARARGS | METH_KEYWORDS, NULL },
    { "decrypt", (PyCFunction)PyTwofish_decrypt, METH_VARARGS | METH_KEYWORDS, NULL },
    { NULL }
};


PyTypeObject PyTwofishType = {
    .ob_base = PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = PYNAME_CONCAT(MODULENAME__MINICRYPTO, CLASSNAME_TWOFISH),
    .tp_doc = NULL,
    .tp_basicsize = sizeof(PyTwofishObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = PyTwofish_new,
    .tp_init = (initproc)PyTwofish_init,
    .tp_methods = PyTwofish_methods,
};

/* end class Twofish */


/* class Weakfish */

struct _PyWeakfishObject {
    PyCipherObject base;
};


static void _Weakfish_encrypt(PyWeakfishObject* Py_UNUSED(self), uint8_t dst[CIPHER_BLOCKSIZE], uint8_t src[CIPHER_BLOCKSIZE]) {
    Weakfish_encrypt(src, dst);
}

static void _Weakfish_decrypt(PyWeakfishObject* Py_UNUSED(self), uint8_t dst[CIPHER_BLOCKSIZE], uint8_t src[CIPHER_BLOCKSIZE]) {
    Weakfish_decrypt(src, dst);
}


static PyObject* PyWeakfish_new(PyTypeObject* type, PyObject* Py_UNUSED(args), PyObject* Py_UNUSED(kwds)) {
    PyWeakfishObject* self = (PyWeakfishObject*)type->tp_alloc(type, 0);
    if (self) {
        _Cipher_override((PyCipherObject*)self, (cipherproc)_Weakfish_encrypt, (cipherproc)_Weakfish_decrypt);
    }
    return (PyObject*)self;
}

static int PyWeakfish_init(PyWeakfishObject* Py_UNUSED(self), PyObject* args, PyObject* kwds) {
    static char* kwlist[] = { NULL };

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "", kwlist)) {
        return -1;
    }
    return 0;
}


static PyObject* PyWeakfish_encrypt(PyWeakfishObject* self, PyObject* args, PyObject* kwds) {
    return _PyCipher_cryptoproc((PyCipherObject*)self, args, kwds, (cipherproc)_Weakfish_encrypt);
}

static PyObject* PyWeakfish_decrypt(PyWeakfishObject* self, PyObject* args, PyObject* kwds) {
    return _PyCipher_cryptoproc((PyCipherObject*)self, args, kwds, (cipherproc)_Weakfish_decrypt);
}

static PyMethodDef PyWeakfish_methods[] = {
    { "encrypt", (PyCFunction)PyWeakfish_encrypt, METH_VARARGS | METH_KEYWORDS, NULL },
    { "decrypt", (PyCFunction)PyWeakfish_decrypt, METH_VARARGS | METH_KEYWORDS, NULL },
    { NULL }
};


PyTypeObject PyWeakfishType = {
    .ob_base = PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = PYNAME_CONCAT(MODULENAME__MINICRYPTO, CLASSNAME_WEAKFISH),
    .tp_doc = NULL,
    .tp_basicsize = sizeof(PyWeakfishObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = PyWeakfish_new,
    .tp_init = (initproc)PyWeakfish_init,
    .tp_methods = PyWeakfish_methods,
};

/* end class Weakfish */
