CVE Telegram Bot
================

Overview
--------

This Python script implements a Telegram bot that provides information about Common Vulnerabilities and Exposures (CVEs) and Common Platform Enumeration (CPE) entries. The bot allows users to search for CVEs based on keywords, retrieve details about a specific CVE by its ID, and obtain information about CPEs. Users can also follow specific CPEs to receive updates on new CVEs related to them.

Prerequisites
-------------

Before running the bot, ensure you have the required dependencies installed:

-   `python-telegram-bot`: Install using `pip install python-telegram-bot`.
-   `nvdlib`: Install using `pip install nvdlib`.
-   `matplotlib`: Install using `pip install matplotlib`.
-   `reportlab`: Install using `pip install reportlab`.
-   `mysql-connector-python`: Install using `pip install mysql-connector-python`.

Configuration
-------------

1.  Replace the placeholder token in the script with your Telegram Bot API token:

    pythonCopy code

    `TOKEN: Final = 'YOUR_TELEGRAM_BOT_TOKEN'`

2.  Ensure you have a MySQL database set up and replace the database connection details in the script:

    pythonCopy code

    `database_connection = mysql.connector.connect(
        host="YOUR_DB_HOST",
        user="YOUR_DB_USER",
        password="YOUR_DB_PASSWORD",
        database="YOUR_DB_NAME"
    )`

3.  Customize the bot username:

    pythonCopy code

    `BOT_USERNAME: Final = '@YourBotUsername'  # Update with your bot's username`

Database Initialization
-----------------------

The script creates the necessary tables in the MySQL database for caching CVE and CPE results. Make sure your database server is running, and the provided connection details are correct.

Running the Bot
---------------

Run the script to start the bot:

bashCopy code

`python your_script_name.py`

Commands
--------

-   `/cve keyword <keyword>`: Search for CVEs by a keyword.
-   `/cve id <cve_id>`: Get the description and score for a specific CVE.
-   `/cpe keyword <keyword>`: Search for CPEs by a keyword.
-   `/cpe id <cpe_name>`: Get information about a specific CPE.
-   `/follow <cpe_name>`: Follow a specific CPE for updates.
-   `/unfollow <cpe_name>`: Unfollow a previously followed CPE.
-   `/subscriptions`: View the list of CPEs you are currently following.
-   `/update`: Get updates on new CVEs for the CPEs you are following in the latest month.
-   `/help`: Display the help message.

Additional Notes
----------------

-   The bot responds to common greetings and inquiries.
-   Error handling is implemented to address server connection issues and invalid commands.

Feel free to customize the script to meet your specific requirements or add additional functionality. If you encounter any issues, refer to the error handling section for guidance.