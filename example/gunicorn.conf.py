import multiprocessing

worker_class = "eventlet"
workers = multiprocessing.cpu_count()*2+1
bind = "0.0.0.0:8000"
timeout = 90
keepalive = 3600
