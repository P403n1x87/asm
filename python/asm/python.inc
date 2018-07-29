;; ---------------------------------------------------------------------------
;; EXTERNAL SYMBOLS
;; ---------------------------------------------------------------------------

EXTERN    PyModule_Create2
EXTERN    _Py_NoneStruct


;; ---------------------------------------------------------------------------
;; CONSTANTS
;; ---------------------------------------------------------------------------

NULL                          equ 0x0
PYTHON_API_VERSION            equ 1013
METH_NOARGS                   equ 0x4


;; ---------------------------------------------------------------------------
;; STRUCURES
;; ---------------------------------------------------------------------------

STRUC PyMethodDef
  .ml_name              resq 1    ; const char *
  .ml_meth              resq 1    ; PyCFunction
  .ml_flags             resq 1    ; int
  .ml_doc               resq 1    ; const char *
ENDSTRUC

STRUC PyObject
  .ob_refcnt            resq 1    ; Py_ssize_t
  .ob_type              resq 1    ; struct _typeobject *
ENDSTRUC

STRUC PyModuleDef_Base
  .ob_base              resb PyObject_size
  .m_init               resq 1    ; PyObject *
  .m_index              resq 1    ; Py_ssize_t
  .m_copy               resq 1    ; PyObject *
ENDSTRUC

STRUC PyModuleDef
  .m_base               resb PyModuleDef_Base_size
  .m_name               resq 1    ; const char *
  .m_doc                resq 1    ; const char *
  .m_size               resq 1    ; Py_ssize_t
  .m_methods            resq 1    ; PyMethodDef *
  .m_slots              resq 1    ; struct PyModuleDef_Slot *
  .m_traverse           resq 1    ; traverseproc
  .m_clear              resq 1    ; inquiry
  .m_free               resq 1    ; freefunc
ENDSTRUC


;; ---------------------------------------------------------------------------
;; MACROS
;; ---------------------------------------------------------------------------

%define NullMethodDef         dq NULL, NULL, 0, NULL

%define PyModuleDef_HEAD_INIT dq 1, NULL, NULL, 0, NULL

%define Py_None               _Py_NoneStruct
