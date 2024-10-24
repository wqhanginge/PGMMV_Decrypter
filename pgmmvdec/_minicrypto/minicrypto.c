#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "minicrypto.h"
#include "cipher.h"
#include "cipher_iter.h"
#include "cipher_mode.h"


/* general functions */

void minicrypto_xor_bytes(uint8_t* ret, uint8_t* ba, uint8_t* bb, size_t len) {
    for (size_t offset = 0; offset < len; offset++) {
        ret[offset] = ba[offset] ^ bb[offset];
    }
}

/* end general functions */


/* module _minicrypto */

static PyObject* Py_minicrypto_xor_bytes(PyObject* self, PyObject* args, PyObject* kwds) {
    static char* kwlist[] = { "bytes1", "bytes2", "strict", NULL };

    Py_buffer bytes1, bytes2;
    int strict = 0;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "y*y*|$p", kwlist, &bytes1, &bytes2, &strict)) {
        return NULL;
    }
    if (strict && bytes1.len != bytes2.len) {
        PyErr_SetString(PyExc_ValueError, "Length not equal");
        PyBuffer_Release(&bytes1);
        PyBuffer_Release(&bytes2);
        return NULL;
    }

    Py_buffer* psbytes = (bytes1.len < bytes2.len) ? &bytes1 : &bytes2;
    Py_buffer* plbytes = (bytes1.len < bytes2.len) ? &bytes2 : &bytes1;
    size_t slen = psbytes->len, llen = plbytes->len;

    uint8_t* buffer = (uint8_t*)malloc(slen * 2 + llen);
    if (!buffer) {
        PyBuffer_Release(&bytes1);
        PyBuffer_Release(&bytes2);
        return PyErr_NoMemory();
    }

    uint8_t* sinput = buffer + slen, * linput = buffer + slen * 2;
    if (PyBuffer_ToContiguous(sinput, psbytes, slen, 'C') < 0) {
        PyBuffer_Release(&bytes1);
        PyBuffer_Release(&bytes2);
        free(buffer);
        return NULL;
    }
    if (PyBuffer_ToContiguous(linput, plbytes, llen, 'C') < 0) {
        PyBuffer_Release(&bytes1);
        PyBuffer_Release(&bytes2);
        free(buffer);
        return NULL;
    }
    PyBuffer_Release(&bytes1);
    PyBuffer_Release(&bytes2);

    minicrypto_xor_bytes(buffer, sinput, linput, slen);

    PyObject* result = PyBytes_FromStringAndSize(buffer, slen);
    free(buffer);
    return result;
}

static PyMethodDef Py_minicrypto_methods[] = {
    { "xor_bytes", (PyCFunction)Py_minicrypto_xor_bytes, METH_VARARGS | METH_KEYWORDS, NULL },
    { NULL }
};


static PyModuleDef Py_minicrypto_module = {
    .m_base = PyModuleDef_HEAD_INIT,
    .m_name = MODULENAME__MINICRYPTO,
    .m_doc = NULL,
    .m_size = -1,
    .m_methods = Py_minicrypto_methods,
};

/* end module _minicrypto */


typedef struct _PyTypeList {
    const char* name;
    PyTypeObject* type;
} PyTypeList;


static PyTypeList typelist[] = {
    { CLASSNAME_CIPHER, &PyCipherType },
    { CLASSNAME_TWOFISH, &PyTwofishType },
    { CLASSNAME_WEAKFISH, &PyWeakfishType },
    { CLASSNAME_CIPHERITER, &PyCipherIterType },
    { CLASSNAME_CBCITER, &PyCBCIterType },
    { CLASSNAME_CIPHERMODE, &PyCipherModeType },
    { CLASSNAME_CBC, &PyCBCType },
    { NULL }
};

PyMODINIT_FUNC PyInit__minicrypto() {
    cipher_type_ready();
    cipher_iter_type_ready();
    cipher_mode_type_ready();

    PyObject* mod = PyModule_Create(&Py_minicrypto_module);
    if (mod) {
        for (size_t idx = 0; typelist[idx].name; idx++) {
            if (PyModule_AddObjectRef(mod, typelist[idx].name, (PyObject*)typelist[idx].type) < 0) {
                Py_DECREF(mod);
                return NULL;
            }
        }
        cipher_initialize();
    }
    return mod;
}
