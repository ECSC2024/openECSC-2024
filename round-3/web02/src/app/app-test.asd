(defsystem "app-test"
  :defsystem-depends-on ("prove-asdf")
  :author "Simone Cimarelli"
  :license ""
  :depends-on ("app"
               "prove")
  :components ((:module "tests"
                :components
                ((:test-file "app"))))
  :description "Test system for app"
  :perform (test-op (op c) (symbol-call :prove-asdf :run-test-system c)))
