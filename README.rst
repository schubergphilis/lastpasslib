===========
lastpasslib
===========

A library able to retrieve and decrypt all items in lastpass along with their change history and attachments.


* Documentation: https://lastpasslib.readthedocs.org/en/latest


Project Features
================

* Can completely decrypt all secrets, attachments, and all history of every field that supports it.
* Can save the blob locally.
* Can save attachments of secrets.
* Exposes share info to and from people.

Project Inspiration
===================


Initial inspiration was taken from https://github.com/konomae/lastpass-python. More features were needed and I could not
really follow the design of that project so well, so I ended up rewriting all of it with a new design that made sense to
me and implemented all the required features on that. This project is now quite further that the original project feature wise.

During my reverse engineering efforts I also found https://github.com/cfbao/lastpass-vault-parser/blob/master/lastpass-vault-format.md
sadly a little too late. Also extended my model further than the documentation of that project.
