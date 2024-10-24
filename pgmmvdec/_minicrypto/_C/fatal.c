#define PY_SSIZE_T_CLEAN
#include <Python.h>


/* general fatal function */

void cipher_fatal(const char* msg) {
    Py_FatalError(msg);
}
