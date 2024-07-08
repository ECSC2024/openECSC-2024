worker_class = "eventlet"

# Listen on port 80
bind         = "0.0.0.0:80"

keepalive    = 30
accesslog    = "-"
workers      = 4
user         = "web"