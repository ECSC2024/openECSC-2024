(ql:quickload :app)

(defpackage app.app
  (:use :cl)
  (:import-from :lack.builder
                :builder)
  (:import-from :ppcre
                :scan
                :regex-replace)
  (:import-from :app.web
                :*web*)
  (:import-from :app.config
                :config
                :productionp
                :*static-directory*))
(in-package :app.app)

(builder
  (:static
   :path (lambda (path)
           (if (ppcre:scan "^(?:/images/|/css/|/js/|/robot\\.txt$|/favicon\\.ico$)" path)
               path
               nil))
   :root *static-directory*)
  :accesslog
  (list :backtrace :output (getf (config) :error-log))
  *web*)
