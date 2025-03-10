CCF Development Setup
=====================

Environment Setup
-----------------

First, on your development VM, checkout the CCF repository or :doc:`install the latest CCF release </build_apps/install_bin>`.

Then, to quickly set up the dependencies necessary to build CCF itself and CCF applications, simply run:

.. tab:: SNP

    .. code-block:: bash

        $ cd <ccf_path>/getting_started/setup_vm
        $ ./run.sh ccf-dev.yml

.. tab:: Virtual

    .. warning:: The `virtual` version of CCF can also be run on hardware that does not support SEV-SNP. Virtual mode does not provide any security guarantees and should be used for development purposes only.

    .. code-block:: bash

        $ cd <ccf_path>/getting_started/setup_vm
        $ ./run.sh ccf-dev.yml

Once this is complete, you can proceed to :doc:`/build_apps/build_app`.

Build Container
---------------

The quickest way to get started building CCF applications is to use the CCF build container. It contains all the dependencies needed to build and test CCF itself as well as CCF applications.

.. code-block:: bash

    $ export VERSION="4.0.0"
    $ export PLATFORM="snp" # snp or virtual
    $ docker pull mcr.microsoft.com/ccf/app/dev:$VERSION-$PLATFORM

The container contains the latest release of CCF along with a complete build toolchain, and startup scripts.

.. note::

    - `virtual` mode provides no security guarantee. It is only useful for development and prototyping.

Visual Studio Code Setup
~~~~~~~~~~~~~~~~~~~~~~~~

If you use `Visual Studio Code`_ you can install the `Remote Container`_ extension and use the sample :ccf_repo:`devcontainer.json <.devcontainer/devcontainer.json>` config.
`More details on that process <https://code.visualstudio.com/docs/remote/containers#_quick-start-open-a-git-repository-or-github-pr-in-an-isolated-container-volume>`_.


.. _`Visual Studio Code`: https://code.visualstudio.com/
.. _`Remote Container`: https://code.visualstudio.com/docs/remote/containers

