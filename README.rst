================
qca-hex-analyzer
================

qca-hex-analyzer is a tool used to analyze hexdumps produced by a
qca wireless kernel driver (such as ath6kl or qcacld2.0).
The hexdumps are assumed to contain dumps of the data traffic
between the driver and the target.
No special preprocessing of the log files is required.
Filter strings can be used to limit the output
(only RX or TX etc.).
The driver must of course be configured to log all necessary debug
data (for ath6kl this means a proper debug mask).


* GitHub: https://github.com/erstrom/qca-hex-analyzer

Installing
----------

Installing dependency: hexfilter
################################

qca-hex-analyzer is depending on another tool/library called hexfilter.
hexfilter is used to filter out the actual hex dumps from the logs.

System install:

.. code-block:: bash

    $ git clone https://github.com/erstrom/hexfilter.git
    $ cd hexfilter
    $ sudo python setup.py install

or, if prefered, installation into a virtual environment:

.. code-block:: bash

    $ git clone https://github.com/erstrom/hexfilter.git
    $ virtualenv venv
    $ . venv/bin/activate
    $ cd hexfilter
    $ python setup.py install

Note that installing into the virtual environment does not require root
priveleges.

The above installation requires the python package python-virtualenv.
On Debian/Ubuntu the easiest way to install it is:

.. code-block:: bash

    $ sudo apt-get install python-virtualenv

Installing dependency: enum34
#############################

In case a Python version prior to 3.4 is used, the package enum34 must
be installed. This is a backport of the enum package that comes with
Python 3.4

Below shows how to install enum34:

.. code-block:: bash

    $ pip install enum34

The above installation requires the python package python-pip.
On Debian/Ubuntu the easiest way to install it is:

.. code-block:: bash

    $ sudo apt-get install python-pip


Installing qca-hex-analyzer
###########################

qca-hex-analyzer is installed in the same way as hexfilter.

If hexfilter was installed into a virtual environment, qca-hex-analyzer
must be installed into the same virtual env:

.. code-block:: bash

    $ git clone https://github.com/erstrom/qca-hex-analyzer.git
    $ . venv/bin/activate
    $ cd qca-hex-analyzer
    $ python setup.py install
