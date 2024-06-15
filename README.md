# securechatsample
A secure Chat Sample.

## Prerequisite
1. Python
2. Pip

## How to run?
Run this command first, so your env kept clean
``python -m virtualenv venv``

Then source the venv by running
``source venv/bin/activate``

Install the requirements
``pip install -r requirements.txt``

Running the application
Open 2 command line prompt or ZSH
1. Run Server first on the first tab:
``python server.py``
2. Run the app on the second tab:
``python app.py``

Make sure the server is fully up before running the app.

Side Note:
If you want to change the where the host and port or any configuration want to be added,
please put it in the *config.py* to kept the code clean.
