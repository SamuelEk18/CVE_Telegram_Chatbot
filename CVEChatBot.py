"""Telegram Bot code by Samuel Ek"""

import re
import io
import asyncio
import datetime as dt
from typing import Final
from functools import partial
import nvdlib
from matplotlib import pyplot as plt
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from telegram import InputFile, Update
from reportlab.pdfgen import canvas
from requests.exceptions import ReadTimeout
import reportlab.lib.pagesizes as rlp
from reportlab.lib import colors
import mysql.connector


TOKEN: Final = 'YOUR_BOT_TOKEN'
BOT_USERNAME: Final = '@CVEChatBot'  # For group chat

database_connection = mysql.connector.connect(
    host="sql11.freemysqlhosting.net", # Change depending on where the sql server is
    user="USERNAME",
    password="PASSWORD",
    database ="DATABSE"
)

database_cursor = database_connection.cursor()

database_cursor.execute('''
    CREATE TABLE IF NOT EXISTS cached_cve_results (
        keyword VARCHAR(255) NOT NULL,
        result_text TEXT NOT NULL,
        PRIMARY KEY (keyword)
    )
''')

database_cursor.execute('''
    CREATE TABLE IF NOT EXISTS cached_cpe_results (
        keyword VARCHAR(255) NOT NULL,
        result_text TEXT NOT NULL,
        PRIMARY KEY (keyword)
    )
''')

database_cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        chat_id BIGINT NOT NULL,
        PRIMARY KEY (chat_id)
    )
''')

database_cursor.execute('''
    CREATE TABLE IF NOT EXISTS followed_cpes (
        user_chat_id BIGINT NOT NULL,
        cpe_name VARCHAR(255) NOT NULL,
        cves VARCHAR(255),
        follow_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (user_chat_id, cpe_name),
        FOREIGN KEY (user_chat_id) REFERENCES users (chat_id)
    )
''')

database_cursor.execute('''
    CREATE TABLE IF NOT EXISTS cpe_severity_counts (
        cpe_name VARCHAR(255) NOT NULL,
        low_count INT NOT NULL,
        medium_count INT NOT NULL,
        high_count INT NOT NULL,
        critical_count INT NOT NULL,
        PRIMARY KEY (cpe_name),
        FOREIGN KEY (cpe_name) REFERENCES cached_cpe_results (keyword)
    )
''')

async def CVE_command(update: Update, context: ContextTypes.DEFAULT_TYPE):

    argument: str = context.args[0] if context.args else None
    if context.args and len(context.args) > 1:
        argument2: str = ' '.join(context.args[1:])
    else:
        argument2 = None

    if not argument or not argument2:
        await update.message.reply_text('Please provide keywords to search for CVEs. For example: "/cve keyword bots".\n Need any assistance, use /help')
        return

    if argument == 'keyword':
        keyword = argument2.lower()

        # Check if the result is already cached in the database
        database_cursor.execute('SELECT result_text FROM cached_cve_results WHERE keyword = %s', (keyword,))
        cached_result = database_cursor.fetchone()

        if cached_result:
            await update.message.reply_text(f'Result for keyword {argument2} (cached):\n\n{cached_result[0]}')
            return

        await update.message.reply_text('Keyword search CVE loading...')
        MAX_RETRIES = 3
        CVE_limit = 30
        for attempt in range(MAX_RETRIES):
            try:
                loop = asyncio.get_event_loop()
                partial_func = partial(nvdlib.searchCVE, keywordSearch = argument2, key='56afd74f-57b6-4de0-8f26-7857e70476f3', delay=0.6, limit = CVE_limit)
                CVE_search = await loop.run_in_executor(None, partial_func)
                break
            except ReadTimeout:
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(1)
                    continue
        if not CVE_search:
            await update.message.reply_text(f'No CVEs found for keyword: {argument2}')
            return

        # Display information about the found CVEs
        reply = ""
        for eachCVE in CVE_search:
            current_cve_info = f"{eachCVE.id}\n"
            reply += current_cve_info

        # Save the result to the MySQL database
        database_cursor.execute('INSERT INTO cached_cve_results (keyword, result_text) VALUES (%s, %s)', (keyword, reply))
        database_connection.commit()

        await update.message.reply_text(f'Result for keyword: "{argument2}"\n\n{reply}')

    if argument == 'id':
        cve_id = argument2.lower()

        # Check if the result is already cached in the database
        database_cursor.execute('SELECT result_text FROM cached_cve_results WHERE keyword = %s', (cve_id,))
        cached_result = database_cursor.fetchone()

        if cached_result:
            await update.message.reply_text(f'Result for CVE ID {argument2} (cached):\n\n{cached_result[0]}')
            return
        

        await update.message.reply_text(f'Description for {argument2} are being loaded...')
        MAX_RETRIES = 3
        for attempt in range(MAX_RETRIES):
            try:
                loop = asyncio.get_event_loop()
                partial_func = partial(nvdlib.searchCVE, cveId=argument2, key='56afd74f-57b6-4de0-8f26-7857e70476f3', delay=0.6)
                CVE_search = (await loop.run_in_executor(None, partial_func))[0]
                break
            except ReadTimeout:
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(1)
                    continue
        if not CVE_search:
            await update.message.reply_text(f'No CVEs found for keyword: {argument2}')
            return
        
        # Display information about the found CVEs
        reply_description = CVE_search.descriptions[0].value
        reply_score = ' '.join(map(str, CVE_search.score))
        reply_https = CVE_search.url
        reply_total = f'Description:\n\n{reply_description}\n\nScore: \n{reply_score}\n\nLink to NIST database page: {reply_https}'

        
        # Save the result to the MySQL database
        database_cursor.execute('INSERT INTO cached_cve_results (keyword, result_text) VALUES (%s, %s)', (cve_id, reply_total))
        database_connection.commit()

        await update.message.reply_text(reply_total)
    
async def generate_and_send_graph(update: Update, cpe_name: str, severity_counts: tuple):
    labels = ['Low', 'Medium', 'High', 'Critical']
    values = list(severity_counts)
    plt.bar(labels, values)
    plt.xlabel('Severity')
    plt.ylabel('Number of CVEs')
    plt.title(cpe_name)

    img = io.BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    
    await update.message.reply_photo(img)

async def CPE_Command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    argument1: str = context.args[0] if context.args else None
    if context.args and len(context.args) > 1:
        argument2: str = ' '.join(context.args[1:])
    else:
        argument2 = None

    if not argument1 or not argument2:
        await update.message.reply_text('Please provide keywords. For example: "/cpe id ...".\n Need any assistance, use /help')
        return
 
    if argument1 == 'id':
        cpe_name = argument2.lower()

        # Check if the result is already cached in the database
        database_cursor.execute('SELECT result_text FROM cached_cpe_results WHERE keyword = %s', (cpe_name,))
        cached_result = database_cursor.fetchone()

        if cached_result:
            await update.message.reply_text(f'Result for CPE {argument2} (cached):\n\n{cached_result[0]}')
            
            database_cursor.execute('SELECT low_count, medium_count, high_count, critical_count FROM cpe_severity_counts WHERE cpe_name = %s', (cpe_name,))
            severity_counts = database_cursor.fetchone()

            if severity_counts:
                await generate_and_send_graph(update, cpe_name, severity_counts)
            return

        await update.message.reply_text(f'Searching after CPE {argument2}')
        MAX_RETRIES = 3
        reply = ""
        for attempt in range(MAX_RETRIES):
            try:
                loop = asyncio.get_event_loop()
                partial_func = partial(nvdlib.searchCVE, cpeName=cpe_name, key='56afd74f-57b6-4de0-8f26-7857e70476f3', delay=0.6)
                CPE_search = await loop.run_in_executor(None, partial_func)
                break
            except ReadTimeout:
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(1)
                    continue

        if not CPE_search:
            await update.message.reply_text(f'No CPEs found with id: {argument2}')
            return
        
        sorted_cves = sorted(CPE_search, key=lambda x: x.published, reverse=True)
        top_cves = sorted_cves[:20]

        scores = {'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0}
        for eachCVE in top_cves:
            cve_score = eachCVE.score[2]
            if cve_score == 'LOW':
                scores['Low'] += 1
            if cve_score == 'MEDIUM':
                scores['Medium'] += 1
            if cve_score == 'HIGH':
                scores['High'] += 1
            if cve_score == 'CRITICAL':
                scores['Critical'] += 1

        for eachCVE in top_cves:
            cve_id = eachCVE.id
            score = ' '.join(map(str, eachCVE.score))
            url_link = eachCVE.url
            eachCPE = f"CVE ID: {cve_id}     Score: {score}     {url_link}\n"
            reply += eachCPE

        plt.clf()
        plt.bar(scores.keys(), scores.values())
        plt.xlabel('Severity')
        plt.ylabel('Number of CVEs')
        plt.title(cpe_name)

        img = io.BytesIO()
        plt.savefig(img, format='png')
        img.seek(0)
       
        await update.message.reply_photo(img)

        # Save the result to the MySQL database
        database_cursor.execute('INSERT INTO cached_cpe_results (keyword, result_text) VALUES (%s, %s)', (cpe_name, reply))
        database_cursor.execute('INSERT INTO cpe_severity_counts (cpe_name, low_count, medium_count, high_count, critical_count) VALUES (%s, %s, %s, %s, %s)',
                                (cpe_name, scores['Low'], scores['Medium'], scores['High'], scores['Critical']))
        database_connection.commit()

        await update.message.reply_text(f'Result for the search {argument2}\n\n{reply}')


        # Create a pdf document with CPE information
        lines = re.split(r'\n', reply) # Split 'reply' into a list of lines (to process each line separately)
        pdf_buffer = io.BytesIO()

        pdfname = f'{cpe_name}.pdf'
        pdf_document = canvas.Canvas(pdf_buffer, pagesize=rlp.A4)
        pdf_document.setFillColor(colors.darkblue)
        pdf_document.setFont("Helvetica-Bold", 15)
        pdf_document.drawString(20, 750, f'Description for {cpe_name}:')

        pdf_document.setFillColor(colors.black)
        pdf_document.setFont("Helvetica", 12)
        y_position = 700
        for line in lines:
            pdf_document.drawString(20, y_position, line)
            y_position -= 12  

        pdf_document.save()
        pdf_buffer.seek(0)
        await update.message.reply_document(document=InputFile(pdf_buffer, filename=pdfname))


    if argument1 == 'keyword':
        keyword = argument2.lower()

        # Check if the result is already cached in the database
        database_cursor.execute('SELECT result_text FROM cached_cpe_results WHERE keyword = %s', (keyword,))
        cached_result = database_cursor.fetchone()

        if cached_result:
            await update.message.reply_text(f'Result for CPE keyword {argument2} (cached):\n\n{cached_result[0]}')
            return

        await update.message.reply_text(f'Searching after CPE keyword "{argument2}"')
        MAX_RETRIES = 3
        reply = ""
        for attempt in range(MAX_RETRIES):
            try:
                loop = asyncio.get_event_loop()
                partial_func = partial(nvdlib.searchCPE, keywordSearch=argument2, key='56afd74f-57b6-4de0-8f26-7857e70476f3', delay=0.6, limit=15)
                CPE_search = await loop.run_in_executor(None, partial_func)
 
                break
            except ReadTimeout:
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(1)
                    continue

        if not CPE_search:
            await update.message.reply_text(f'No CPEs found for keyword: {argument2}')
            return

        # Display information about the found CVEs
        for eachCVE in CPE_search:
            eachCPE = f"{eachCVE.cpeName}\n"
            reply += eachCPE

        # Save the result to the MySQL database
        database_cursor.execute('INSERT INTO cached_cpe_results (keyword, result_text) VALUES (%s, %s)', (keyword, reply))
        database_connection.commit()

        await update.message.reply_text(f'Result for the keyword {argument2}:\n\n{reply}')


# /follow command
async def follow_cpe(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_chat_id = update.message.chat.id
    cpe_name = context.args[0].lower() if context.args else None

    if not cpe_name:
        await update.message.reply_text('Please provide a CPE to follow. For example: /follow cpe_name')
        return
    try:
        database_cursor.execute('SELECT cpe_name FROM followed_cpes WHERE user_chat_id = %s AND cpe_name = %s', (user_chat_id, cpe_name))
        already_following = database_cursor.fetchone()

        if already_following:
            await update.message.reply_text(f'You are already following CPE: {cpe_name}. Use /update to check for updates.')
            return

        await update.message.reply_text(f'Please wait while I search for CVEs related to {cpe_name}. This may take a moment...')

        MAX_RETRIES = 3
        reply = ""
        for attempt in range(MAX_RETRIES):
            try:
                loop = asyncio.get_event_loop()
                partial_func = partial(nvdlib.searchCVE, cpeName=cpe_name, key='56afd74f-57b6-4de0-8f26-7857e70476f3', delay=0.6)
                CPE_search = await loop.run_in_executor(None, partial_func)
                break
            except ReadTimeout:
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(1)
                    continue

        for eachCVE in CPE_search:
            eachCPE = f"{eachCVE.id}\n"
            reply += eachCPE

        # Id for user insertion if not already there, therefore IGNORE
        database_cursor.execute('INSERT IGNORE INTO users (chat_id) VALUES (%s)', (user_chat_id,))
        database_connection.commit()

        # Below saves the CPE in the database and saves the timestamp
        follow_timestamp = dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S') # Specific format
        database_cursor.execute('INSERT INTO followed_cpes (user_chat_id, cpe_name, cves, follow_timestamp) VALUES (%s, %s, %s, %s)',
                                (user_chat_id, cpe_name, reply, follow_timestamp))
        database_connection.commit()

        await update.message.reply_text(f'You are now following CPE: {cpe_name}')

    except mysql.connector.Error as err:
        print(f"Error: {err}")
        await update.message.reply_text('An error occurred while trying to follow the CPE. You might already be following this CPE. Contact developer if this problem persists.')


async def unfollow_cpe(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_chat_id = update.message.chat.id
    cpe_to_unfollow = context.args[0].lower() if context.args else None

    if not cpe_to_unfollow:
        try:
            database_cursor.execute('SELECT cpe_name FROM followed_cpes WHERE user_chat_id = %s', (user_chat_id,))
            followed_cpes = database_cursor.fetchall()
            if not followed_cpes:
                await update.message.reply_text('You are not following any CPEs.')
                return

            followed_cpe_list = '\n\n'.join(cpe_row[0] for cpe_row in followed_cpes)
            await update.message.reply_text(f'You are currently following these CPEs:\n\n{followed_cpe_list}\n\n'
                                              'To unfollow a CPE, use the command: /unfollow <cpe_name>')
            return

        except mysql.connector.Error as err:
            print(f"Error: {err}")
            await update.message.reply_text('An error occurred while trying to fetch followed CPEs. You might not follow this CPE, and therefore not able to unfollow it.')

    try:
        # Unfollow the specified CPE
        database_cursor.execute('DELETE FROM followed_cpes WHERE user_chat_id = %s AND cpe_name = %s',
                                (user_chat_id, cpe_to_unfollow))
        database_connection.commit()

        await update.message.reply_text(f'You have unfollowed CPE: {cpe_to_unfollow}')

    except mysql.connector.Error as err:
        print(f"Error: {err}")
        await update.message.reply_text('An error occurred while trying to unfollow the CPE.')


async def what_cpe_follow(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_chat_id = update.message.chat.id
    try:
        # Retrieve followed CPEs for the user
        database_cursor.execute('SELECT cpe_name FROM followed_cpes WHERE user_chat_id = %s', (user_chat_id,))
        followed_cpes = database_cursor.fetchall()

        if not followed_cpes:
            await update.message.reply_text('You are not following any CPEs.')
            return

        followed_cpe_list = '\n\n'.join(cpe_row[0] for cpe_row in followed_cpes)
        await update.message.reply_text(f'You are currently following these CPEs:\n\n{followed_cpe_list}\n\n')
        return

    except mysql.connector.Error as err:
        print(f"Error: {err}")
        await update.message.reply_text('An error occurred while trying to fetch followed CPEs.')

# Show updates
async def new_cves(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_chat_id = update.message.chat.id

    try:
        # 
        database_cursor.execute('SELECT cpe_name, follow_timestamp FROM followed_cpes WHERE user_chat_id = %s', (user_chat_id,))
        followed_cpes = database_cursor.fetchall()

        if not followed_cpes:
            await update.message.reply_text('You are not following any CPEs.')
            return

        for cpe_row in followed_cpes:
            cpe_name, follow_timestamp = cpe_row
            await update.message.reply_text(f"Please wait while I check for updates for {cpe_name}. This may take a moment...")
            # Check if follow_timestamp is already a datetime object
            if not isinstance(follow_timestamp, dt.datetime):
                # Convert follow_timestamp to datetime object
                follow_timestamp = dt.datetime.strptime(follow_timestamp, '%Y-%m-%d %H:%M:%S')

            start = follow_timestamp
            end = dt.datetime.now()

            database_cursor.execute('SELECT cves FROM followed_cpes WHERE user_chat_id = %s AND cpe_name = %s', (user_chat_id, cpe_name))
            stored_cves = set(row[0] for row in database_cursor.fetchall())

            MAX_RETRIES = 3
            for attempt in range(MAX_RETRIES):
                try:
                    loop = asyncio.get_event_loop()
                    partial_func = partial(nvdlib.searchCVE, cpeName=cpe_name, pubStartDate=start, pubEndDate=end, key='56afd74f-57b6-4de0-8f26-7857e70476f3', delay=0.6)
                    cve_search = await loop.run_in_executor(None, partial_func)
                    break
                except ReadTimeout:
                    if attempt < MAX_RETRIES -1:
                        await asyncio.sleep(1)
                        continue
            new_cves = []
            for cve in cve_search:
                if cve.id not in stored_cves:
                    new_cves.append(cve)
                        
            if new_cves:
                # Save the new CVEs to the database
                database_cursor.executemany('INSERT INTO followed_cpes (user_chat_id, cpe_name, cve_id) VALUES (%s, %s, %s)', [(user_chat_id, cpe_name, cve.id) for cve in new_cves])
                database_connection.commit()

                await update.message.reply_text(f"There are new CVEs for {cpe_name} in the last month:")
                for eachCVE in new_cves:
                    await update.message.reply_text(f"{eachCVE.id}")
                
                # Generate graph for new CVEs
                severity_counts = {'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0}
                for eachCVE in new_cves:
                    cve_score = eachCVE.score[2]
                    if cve_score == 'LOW':
                        severity_counts['Low'] += 1
                    elif cve_score == 'MEDIUM':
                        severity_counts['Medium'] += 1
                    elif cve_score == 'HIGH':
                        severity_counts['High'] += 1
                    elif cve_score == 'CRITICAL':
                        severity_counts['Critical'] += 1
                await generate_and_send_graph(update, cpe_name, tuple(severity_counts.values))
            else:
                await update.message.reply_text(f'No new CVEs for {cpe_name} in the last month.')

    except mysql.connector.Error as err:
        print(f"Error: {err}")
        await update.message.reply_text('An error occurred while trying to fetch new CVEs.')



async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    help_string = (
        '*I am here to help you manage the CVE Chatbot\\. '
        'If you are new to the Bot, please see the commands below\\.*\n\n'
        'You can control me by sending these commands with arguments:\n\n'
        '\\- /cve keyword \\<keyword\\> \\- Search for CVEs by a keyword\\.\n\n'
        '\\- /cve id \\<cve\\_id\\> \\- Get the description and score for a specific CVE\\.\n\n'
        '_*For example:*_\n'
        '```\n'
        '/cve keyword apple 2022\n'
        '```'
        '```\n'
        '/cve id CVE\\-2022\\-1234\n'
        '```\n'
        'You can also use the command /cpe to show info about CPEs and their specific CVE and more\\. Same use as /cve\\:\n'
        '```\n'
        '/cpe keyword bots 2022\n'
        '```\n'
        '```\n'
        '/cpe id cpe:2\\.3:o:apple:macos:10\\.15\\.7:security\\_update\\_2022\\-001:*:*:*:*:*:*\n'
        '```\n'
        '\\- /follow \\<cpe\\_name\\> \\- Follow a specific CPE for updates\\.\n'
        '```\n'
        '/follow cpe:2\\.3:o:apple:macos:10\\.15\\.7:security\\_update\\_2022\\-001:*:*:*:*:*:*\n'
        '```\n'
        '\\- /unfollow \\<cpe\\_name\\> \\- Unfollow a previously followed CPE\\.\n'
        '```\n'
        '/unfollow cpe:2\\.3:o:apple:macos:10\\.15\\.7:security\\_update\\_2022\\-001:*:*:*:*:*:*\n'
        '```\n'
        '\\- /subscriptions \\- View the list of CPEs you are currently following\\.\n\n'
        '\\- /update \\- Get updates on new CVEs for the CPEs you are following for the latest month\\.\n\n'
        '\\- /help \\- Display this help message\\.\n\n'
    )
    await update.message.reply_text(help_string, parse_mode='MarkdownV2')

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Hello! What can I do for you today? :)")

def handle_response(text: str) -> str:
    processed: str = text.lower()

    if 'what are your purpose?' in processed:
        return 'I am here for your assistance'

    if 'hello' in processed:
        return 'Hey there!'

    if 'how are you' in processed:
        return 'I am good! How are you?'

    return 'Sorry, I did not understand that. Please try again!'

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message_type: str = update.message.chat.type
    text: str = update.message.text

    print(f'User ({update.message.chat.id}) in {message_type}: "{text}"')

    # If in a group chat:
    if message_type == 'group':
        if BOT_USERNAME in text:
            new_text: str = text.replace(BOT_USERNAME, '').strip()
            response: str = handle_response(new_text)
        else:
            return
    # If in private chat:
    else: 
        response: str = handle_response(text)     

    print('Bot: ', response)    
    await update.message.reply_text(response)

# Handle errors
async def error(update: Update, context: ContextTypes.DEFAULT_TYPE):
    print(f"Update {update} caused error {context.error}\n\n")
    if "503" in str(context.error):
        await update.message.reply_text('Server connection to NIST database lost, try again!')
    if "404" in str(context.error):
        await update.message.reply_text('Invalid command to NIST server. Try again!')


if __name__ == '__main__':

    print("Starting bot...")
    
    app = Application.builder().token(TOKEN).concurrent_updates(True).build()

    app.add_handler(CommandHandler('cpe', CPE_Command))
    app.add_handler(CommandHandler('cve', CVE_command))  
    app.add_handler(CommandHandler('help', help_command))
    app.add_handler(CommandHandler('follow', follow_cpe))
    app.add_handler(CommandHandler('unfollow', unfollow_cpe))
    app.add_handler(CommandHandler('subscriptions', what_cpe_follow))
    app.add_handler(CommandHandler('update', new_cves))
    app.add_handler(CommandHandler('start', start_command))
    app.add_handler(MessageHandler(filters.TEXT, handle_message))

    app.add_error_handler(error)

    print("Polling...")
    app.run_polling(poll_interval=1)
