# microc

Welcome to microc. Your favourite micro container environment.

## Kickstart

```console
python microc.py -- ls -l
 
 Timestamp     PID     UID:GID      Process Message
  0.027805  434727    1000:1000    [parent]  preparing namespaces..............................[DONE] (took 162.9us)
  0.028017  434727   65534:65534   [parent]  forking and waiting for child.....................[WAIT]
  0.029198       1   65534:65534   [ child]  preparing user....................................[DONE] (took 189.1us)
  0.029484       1    1000:1000    [ child]  mounting /proc....................................[DONE] (took 174.9us)
  0.029674       1    1000:1000    [ child]  running 'ls -l'
total 41204
-rw-rw-r--  1 coutinho coutinho      124 Nov  9 19:04 README.md
-rw-rw-r--  1 coutinho coutinho       93 Nov  9 18:53 config.toml
drwxrwxr-x  2 coutinho coutinho     4096 Nov  9 19:01 future
-rw-r--r--  1 coutinho coutinho     5214 Nov  9 18:59 microc.py
  0.032349  434727    1000:1000    [parent]  Child finished!
```

I can see you're not very impressed. No wonder! You just ran ls in a subprocess.

Notice, though, that it ran with PID 1. That's your first step torwards isolation.

## Separate file system

Now let's setup a different root filesystem.

Setup one with:

```console
docker create --name py314-alpine python:3.14-alpine
docker export py314-alpine -o py314-alpine.tar
docker rm py314-alpine
mkdir py314-alpine
tar -xvf py314-alpine.tar -C py314-alpine/
rm py314-alpine.tar

Let's use the config.toml to helps us make the command line shorter

Run: 

```console
python microc.py --config=./config.toml -- python

 Timestamp     PID     UID:GID      Process Message
  0.029043  465098    1000:1000    [parent]  preparing namespaces..............................[DONE] (took 126.5us)
  0.029207  465098   65534:65534   [parent]  forking and waiting for child.....................[WAIT]
  0.030689       1   65534:65534   [ child]  preparing user....................................[DONE] (took 315.3us)
  0.031133       1       1:1000    [ child]  changing root.....................................[DONE] (took 13.8us)
  0.031179       1       1:1000    [ child]  mounting /proc....................................[DONE] (took 198.5us)
  0.031437       1       1:1000    [ child]  running 'python'
Python 3.14.10 (main, Nov  5 2026, 19:26:37) [GCC 15.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> print(os.getpid())
1
>>> print(os.environ)
environ({'TERM': 'xterm', 'PATH': '/usr/local/bin:/usr/bin', 'LC_CTYPE': 'C.UTF-8'})
>>> 

```
