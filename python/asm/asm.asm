DEFAULT                 rel

%include                "asm/python.inc"

GLOBAL                  PyInit_asm:function


;; ---------------------------------------------------------------------------
SECTION                 .rodata
;; ---------------------------------------------------------------------------

l_command_fmt           db "s", 0

l_sayit_name            db "sayit", 0
l_sayit_doc             db "This method has something important to say.", 0
l_sayit_msg             db "Assembly is great fun! :)", 10
l_sayit_msg_len         equ $ - l_sayit_msg

l_module_name           db "asm", 0


;; ---------------------------------------------------------------------------
SECTION                 .data
;; ---------------------------------------------------------------------------

l_asm_methods:              ;; struct PyMethodDef[] *
ISTRUC PyMethodDef
  at PyMethodDef.ml_name    , dq l_sayit_name
  at PyMethodDef.ml_meth    , dq asm_sayit
  at PyMethodDef.ml_flags   , dq METH_VARARGS
  at PyMethodDef.ml_doc     , dq l_sayit_doc
IEND
NullMethodDef

l_asm_module:                ;; struct PyModuleDef *
ISTRUC PyModuleDef
  at PyModuleDef.m_base     , PyModuleDef_HEAD_INIT
  at PyModuleDef.m_name     , dq l_module_name
  at PyModuleDef.m_doc      , dq NULL
  at PyModuleDef.m_size     , dq -1
  at PyModuleDef.m_methods  , dq l_asm_methods
  at PyModuleDef.m_slots    , dq NULL
  at PyModuleDef.m_traverse , dq NULL
  at PyModuleDef.m_clear    , dq 0
  at PyModuleDef.m_free     , dq NULL
IEND

l_command                     dq 0


;; ---------------------------------------------------------------------------
SECTION                 .text
;; ---------------------------------------------------------------------------

asm_sayit: ;; ----------------------------------------------------------------
                        push  rbp
                        mov   rbp, rsp

                        mov   rax, 1                  ; SYS_WRITE
                        mov   rdi, 1                  ; STDOUT
                        mov   rsi, l_sayit_msg
                        mov   rdx, l_sayit_msg_len
                        syscall

                        mov   rax, Py_None
                        inc   QWORD [rax + PyObject.ob_refcnt]

                        pop   rbp
                        ret
;; end asm_sayit


PyInit_asm: ;; --------------------------------------------------------------
                        push  rbp
                        mov   rbp, rsp

                        mov   rsi, PYTHON_API_VERSION
                        mov   rdi, l_asm_module
                        call  PyModule_Create2 WRT ..plt

                        pop   rbp
                        ret
;; end PyInit_asm
