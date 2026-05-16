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

    uint8_t* bytes1, * bytes2;
    Py_ssize_t blen1, blen2;
    int strict = 0;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "y#y#|$p", kwlist, &bytes1, &blen1, &bytes2, &blen2, &strict)) {
        return NULL;
    }
    if (strict && blen1 != blen2) {
        PyErr_SetString(PyExc_ValueError, "Length not equal");
        return NULL;
    }

    size_t olen = (blen1 < blen2) ? blen1 : blen2;
    PyObject* result = PyBytes_FromStringAndSize(NULL, olen);
    if (result) {
        uint8_t* output = PyBytes_AS_STRING(result);
        minicrypto_xor_bytes(output, bytes1, bytes2, olen);
    }
    return result;
}

static PyMethodDef Py_minicrypto_methods[] = {
    { "xor_bytes", (PyCFunction)Py_minicrypto_xor_bytes, METH_VARARGS | METH_KEYWORDS, NULL },
    { NULL }
};


static PyModuleDef Py_minicrypto_module = {
    .m_base = PyModuleDef_HEAD_INIT,
    .m_name = MODULENAME_MINICRYPTO,
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
    { CLASSNAME_IDENTITY, &PyIdentityType },
    { CLASSNAME_TWOFISH, &PyTwofishType },
    { CLASSNAME_WEAKFISH, &PyWeakfishType },
    { CLASSNAME_CIPHERITER, &PyCipherIterType },
    { CLASSNAME_CBCENCITER, &PyCBCEncIterType },
    { CLASSNAME_CBCDECITER, &PyCBCDecIterType },
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
