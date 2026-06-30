grommunio-setup
===============

An interactive setup script for grommunio.

|shield-agpl|_ |shield-release|_ |shield-cov|_ |shield-loc|

Usage
=====

Run ``setup.sh`` as root. It supports openSUSE Leap 15.6 and 16.0 (including the
grommunio-lds appliance); the package repository is selected automatically from
the underlying openSUSE base version.

grommunio Setup is **safe to re-run**. On a system that was already set up it
offers two choices:

* **Reconfigure** (default) — re-applies the configuration idempotently. Existing
  passwords, TLS certificates and data are preserved. Use it to apply updates or
  to add/remove optional roles.
* **Reset from scratch** — deletes all data and sets the system up anew (the
  former behaviour; requires typing ``removealldata`` to confirm).

Adding / removing roles
-----------------------

On a reconfigure run, the feature list (chat, meet, files, office, archive) is
pre-selected to reflect what is currently installed. Tick a role to add it,
untick a role to remove it. Removing a role stops and disables its services and
uninstalls its packages, but **keeps its database and data** so it can be added
back later (its credential/key configuration is preserved under
``/etc/grommunio-common/setup-backup/``).

Persistent state (including secrets) is stored mode ``0600`` in
``/etc/grommunio-common/setup-state.conf``.

.. |shield-agpl| image:: https://img.shields.io/badge/license-AGPL--3.0-green
.. _shield-agpl: LICENSE.txt
.. |shield-release| image:: https://shields.io/github/v/tag/grommunio/grommunio-setup
.. _shield-release: https://github.com/grommunio/grommunio-setup/tags
.. |shield-loc| image:: https://img.shields.io/github/languages/code-size/grommunio/grommunio-setup

Support
=======

Support is available through grommunio GmbH and its partners. See
https://grommunio.com/ for details. A community forum is at
`<https://community.grommunio.com/>`_.

For direct contact and supplying information about a security-related
responsible disclosure, contact `dev@grommunio.com <dev@grommunio.com>`_.

Contributing
============

* https://docs.github.com/en/get-started/quickstart/contributing-to-projects
* Alternatively, upload commits to a git store of your choosing, or export the
  series as a patchset using `git format-patch
  <https://git-scm.com/docs/git-format-patch>`_, then convey the git
  link/patches through our direct contact address (above).
