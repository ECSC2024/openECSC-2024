(in-package :cl-user)
(defpackage app.web
  (:use :cl
        :caveman2
        :caveman2.exception
        :app.config
        :app.view
        :flexi-streams
        :cl-ppcre)
  (:export :*web*))
(in-package :app.web)

(defparameter *flag* "REDACTED")

;;
;; Exception handling

(define-condition verbose-exception (caveman-exception)
  ((reason :initarg :reason :type string :reader exception-reason))
  (:report
   (lambda (condition stream)
     (format stream "~A~%" (exception-reason condition)))))

(defun throw-status (code format-string &rest args)
  (error 'verbose-exception
         :code code
         :reason (apply #'format nil format-string args)))

(defmacro with-internal-server-error (&body body)
  `(handler-case (progn ,@body)
     ((and error (not caveman-exception)) (condition)
       (format t "Unhandled condition: ~S: ~A~%" condition condition)
       #+:SBCL (sb-debug:backtrace)
       (throw-code 500))))

; Just an alias
(defmacro w/500 (&rest rest)
  `(with-internal-server-error ,@rest))

; CANCELLAMI :)

;; Sandboxing & anti-cheat

(defmacro with-anticheat-flag (&body body)
  (let ((flag-format (gensym)))
    `(let* ((,flag-format (load-time-value (uiop:getenv "FLAG") t))
            (*flag* (format nil ,flag-format (random #.(ash 1 32)))))
       ,@body)))

(defparameter *legal-packages*
  (mapcar #'find-package '(:common-lisp :common-lisp-user :app.web)))

(defparameter *illegal-symbols*
  '("*BREAK-ON-SIGNALS*" "*COMPILE-FILE-PATHNAME*"
    "*COMPILE-FILE-TRUENAME*" "*COMPILE-PRINT*" "*COMPILE-VERBOSE*"
    "*DEBUG-IO*" "*DEBUGGER-HOOK*" "*DEFAULT-PATHNAME-DEFAULTS*"
    "*ERROR-OUTPUT*" "*FEATURES*" "*GENSYM-COUNTER*" "*LOAD-PATHNAME*"
    "*LOAD-PRINT*" "*LOAD-TRUENAME*" "*LOAD-VERBOSE*"
    "*MACROEXPAND-HOOK*" "*QUERY-IO*" "*RANDOM-STATE*" "*READTABLE*"
    "*STANDARD-INPUT*" "*STANDARD-OUTPUT*" "*TERMINAL-IO*"
    "*TRACE-OUTPUT*" "ABORT" "ADD-METHOD" "APROPOS" "APROPOS-LIST"
    "BROADCAST-STREAM" "BROADCAST-STREAM-STREAMS" "CALL-METHOD"
    "CALL-NEXT-METHOD" "CATCH" "CHANGE-CLASS" "CLEAR-INPUT"
    "CLEAR-OUTPUT" "CLOSE" "COMPILE" "COMPILE-FILE"
    "COMPILE-FILE-PATHNAME" "DEFINE-COMPILER-MACRO"
    "DEFINE-MODIFY-MACRO" "DEFINE-SETF-EXPANDER" "DEFINE-SYMBOL-MACRO"
    "DEFMACRO" "DEFPACKAGE" "DEFSETF" "DELETE-PACKAGE" "DISASSEMBLE"
    "DO-ALL-SYMBOLS" "DO-EXTERNAL-SYMBOLS" "DO-SYMBOLS" "DRIBBLE"
    "ECHO-STREAM" "ECHO-STREAM-INPUT-STREAM" "ECHO-STREAM-OUTPUT-STREAM"
    "ED" "ENSURE-DIRECTORIES-EXIST" "EVAL" "FDEFINITION" "FILE-AUTHOR"
    "FILE-ERROR" "FILE-ERROR-PATHNAME" "FILE-LENGTH" "FILE-NAMESTRING"
    "FILE-POSITION" "FILE-STREAM" "FILE-STRING-LENGTH" "FILE-WRITE-DATE"
    "FIND-ALL-SYMBOLS" "FIND-PACKAGE" "FIND-RESTART" "FIND-SYMBOL"
    "FINISH-OUTPUT" "FMAKUNBOUND" "FORCE-OUTPUT" "FRESH-LINE" "GENTEMP"
    "GET-DISPATCH-MACRO-CHARACTER" "GET-MACRO-CHARACTER" "IMPORT"
    "IN-PACKAGE" "INSPECT" "INVOKE-DEBUGGER" "INVOKE-RESTART"
    "INVOKE-RESTART-INTERACTIVELY" "LISTEN" "LOAD"
    "LOAD-LOGICAL-PATHNAME-TRANSLATIONS" "MACRO-FUNCTION" "MACROLET"
    "MAKE-PACKAGE" "MAKUNBOUND" "MAP-INTO" "MULTIPLE-VALUE-SETQ"
    "NBUTLAST" "NCONC" "NINTERSECTION" "NRECONC" "NREVERSE"
    "NSET-DIFFERENCE" "NSET-EXCLUSIVE-OR" "NSTRING-CAPITALIZE"
    "NSTRING-DOWNCASE" "NSTRING-UPCASE" "NSUBLIS" "NSUBST" "NSUBST-IF"
    "NSUBST-IF-NOT" "NSUBSTITUTE" "NSUBSTITUTE-IF" "NSUBSTITUTE-IF-NOT"
    "NUNION" "OPEN" "PEEK-CHAR" "POP" "PPRINT" "PPRINT-DISPATCH"
    "PPRINT-EXIT-IF-LIST-EXHAUSTED" "PPRINT-FILL" "PPRINT-INDENT"
    "PPRINT-LINEAR" "PPRINT-LOGICAL-BLOCK" "PPRINT-NEWLINE" "PPRINT-POP"
    "PPRINT-TAB" "PPRINT-TABULAR" "PRIN1" "PRIN1-TO-STRING" "PRINC"
    "PRINC-TO-STRING" "PRINT" "PRINT-NOT-READABLE"
    "PRINT-NOT-READABLE-OBJECT" "PRINT-OBJECT" "PRINT-UNREADABLE-OBJECT"
    "PROBE-FILE" "PSETF" "PSETQ" "PUSH" "PUSHNEW" "READ" "READ-BYTE"
    "READ-CHAR" "READ-CHAR-NO-HANG" "READ-DELIMITED-LIST"
    "READ-FROM-STRING" "READ-LINE" "READ-PRESERVING-WHITESPACE"
    "READ-SEQUENCE" "READTABLE" "READTABLE-CASE" "READTABLEP"
    "REINITIALIZE-INSTANCE" "REMPROP" "RENAME-FILE" "RENAME-PACKAGE"
    "REPLACE" "REQUIRE" "RPLACA" "RPLACD" "SET"
    "SET-DISPATCH-MACRO-CHARACTER" "SET-MACRO-CHARACTER"
    "SET-PPRINT-DISPATCH" "SET-SYNTAX-FROM-CHAR" "SETF" "SETQ" "SHADOW"
    "SHADOWING-IMPORT" "SLEEP" "SORT" "STABLE-SORT" "STEP" "STORE-VALUE"
    "SYMBOL-MACROLET" "SYMBOL-PLIST" "SYNONYM-STREAM"
    "SYNONYM-STREAM-SYMBOL" "TERPRI" "THROW" "TRACE"
    "TRANSLATE-LOGICAL-PATHNAME" "TRANSLATE-PATHNAME" "TRUNCATE"
    "TWO-WAY-STREAM" "TWO-WAY-STREAM-INPUT-STREAM"
    "TWO-WAY-STREAM-OUTPUT-STREAM" "UNEXPORT" "UNINTERN" "UNREAD-CHAR"
    "UNTRACE" "UNUSE-PACKAGE" "UPDATE-INSTANCE-FOR-DIFFERENT-CLASS"
    "UPDATE-INSTANCE-FOR-REDEFINED-CLASS" "USE-PACKAGE"
    "USER-HOMEDIR-PATHNAME" "VARIABLE" "VECTOR-POP" "VECTOR-PUSH"
    "VECTOR-PUSH-EXTEND" "WITH-COMPILATION-UNIT"
    "WITH-INPUT-FROM-STRING" "WITH-OPEN-FILE" "WITH-OPEN-STREAM"
    "WITH-OUTPUT-TO-STRING" "WITH-PACKAGE-ITERATOR"
    "WITH-STANDARD-IO-SYNTAX" "WRITE" "WRITE-BYTE" "WRITE-CHAR"
    "WRITE-LINE" "WRITE-SEQUENCE" "WRITE-STRING"))

(defmacro with-sandboxed-read-eval (&body body)
  `(labels ((illegal-form-p (form)
              (cond
                ((symbolp form)
                 (if (and (not (keywordp form))
                          (or (not (member (symbol-package form) *legal-packages*))
                              (member (symbol-name form) *illegal-symbols* :test #'string=)))
                     form))
                ((listp form)
                 (find-if #'illegal-form-p form))))
            (read-eval (stream sub-character infix-parameter)
              (declare (ignore infix-parameter))
              (assert (char= sub-character #\.))
              (let* ((form (read stream t nil t))
                     (illegal-form (illegal-form-p form)))
                (when illegal-form
                  (throw-status 500 "Illegal symbol ~S~%" illegal-form))
                (eval form))))
     (let ((*readtable* (copy-readtable)))
       (set-dispatch-macro-character #\# #\. #'read-eval)
       ,@body)))

; CANCELLAMI :P

;;
;; Utilities

(defun plistp (plist)
  (and (listp plist)
       (evenp (length plist))))

(defun alistp (alist)
  (and (listp alist)
       (every #'consp alist)))

(defun make-keyword (value)
  (intern (string-upcase (string value))
          :keyword))

(defun allowed-sub-key-char-p (c)
  (or (alphanumericp c)
      (char= c #\-)
      (char= c #\_)))

(defun allowed-sub-char-p (c)
  (char/= c #\{ #\}))

(defun request-body (request)
  (let ((decoded-body (make-flexi-stream (request-raw-body request)
                                         :external-format :utf-8)))
    (make-concatenated-stream
      decoded-body
      (make-string-input-stream (string #\Newline)))))

(defun parse-sexp (stream)
  (let ((*read-eval* nil))
    (with-standard-io-syntax
      (with-sandboxed-read-eval ; CANCELLAMI!
        (with-anticheat-flag    ; CANCELLAMI!
          (read stream))))))

;;
;; Business logic

(defun parse-body ()
  (handler-case
      (parse-sexp (request-body *request*))
    (end-of-file (condition)
      (throw-status 400 "Request body does not contain a well-formed s-expression"))))

(defun apply-substitution (template key value)
  (unless (symbolp key)
    (throw-status 422 "Substitution key ~S is not a symbol~@[ (try ~S)~]." key (ignore-errors (make-keyword key))))
  (unless (stringp value)
    (throw-status 422 "Substitution value ~S is not a string." value))
  (let ((key-string (symbol-name key)))
    (unless (every #'allowed-sub-key-char-p key-string)
      (throw-status 422 "Invalid substitution key ~S. Substitution keys can only contain alphanumeric characters, dashes and underscores." key))
    (unless (every #'allowed-sub-char-p value)
      (throw-status 422 "Invalid substitution value for key ~S. Substitution values cannot contain curly braces." key))
    (let ((sub-regex (format nil "(?i){~A}" key-string)))
      (regex-replace-all sub-regex template value))))

;;
;; Application

(defclass <web> (<app>) ())
(defvar *web* (make-instance '<web>))
(clear-routing-rules *web*)

;;
;; Routing rules

(defroute "/" ()
  (with-internal-server-error
    (render #P"index.html" `(:motd ,*flag*))))

(defroute ("/interpolate" :method :post) (&aux (body (w/500 (parse-body))))
  (with-internal-server-error
    (unless (plistp body)
      (throw-status 422 "Request body must be a plist"))
    (destructuring-bind (&key (template nil template-supplied-p)
                              substitutions
                              &allow-other-keys)
        body
      (unless template-supplied-p
        (throw-status 422 "Must specify a template."))
      (unless (stringp template)
        (throw-status 422 "Template must be a string."))
      (unless (alistp substitutions)
        (throw-status 422 "Substitutions must be an association list."))
      (loop for (key . value) in substitutions
            with result = template
            do (setf result (apply-substitution result key value))
            finally (return result)))))

;;
;; Error pages

(defmethod on-exception ((app <web>) (code (eql 404)))
  (declare (ignore app))
  (merge-pathnames #P"_errors/404.html"
                   *template-directory*))
