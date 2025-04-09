from bs4 import BeautifulSoup
from dotenv import load_dotenv
from email_reply_parser import EmailReplyParser
from email.utils import parsedate_to_datetime, mktime_tz

import ast
import datetime
import mailbox
import ntpath
import os
import quopri
import re
import rules
import sys
import time
import unicodecsv as csv

# Convertește secunde de la epoch în șir de caracteres în format mm/dd/yyyy
def get_date(email, date_format="%m/%d/%Y"):
    date_str = email.get("date")
    if not date_str:  # Dacă nu există data, returnăm un placeholder
        return "Unknown"

    try:
        parsed_date = parsedate_to_datetime(date_str)
        if parsed_date is None:
            return "Unknown"
        return parsed_date.strftime(date_format)
    except Exception:
        return "Unknown"

# Curăță conținutul
def clean_content(content):
    try:
        # Încearcă să decodeze conținutul dacă este în format "quoted-printable"
        content = quopri.decodestring(content).decode(errors="ignore")
    except (ValueError, AttributeError):
        # Dacă nu se poate decoda, tratază conținutul ca șir de caractere
        content = content.decode(errors="ignore")

    try:
        soup = BeautifulSoup(content, "html.parser")
    except Exception:
        return ''
    return ''.join(soup.stripped_strings)

# Obține conținutul email-ului
def get_content(email):
    for part in email.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        content = part.get_payload(decode=True)
        return EmailReplyParser.parse_reply(clean_content(content)) if content else ""

# Obține toate adresele de email dintr-un câmp
def get_emails_clean(field):
    matches = re.findall(r'\<?([a-zA-Z0-9_\-\.]+@[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,5})\>?', str(field))
    return sorted(set(match.lower() for match in matches)) if matches else []

# Punct de intrare
if __name__ == '__main__':
    argv = sys.argv

    # Ignoră argumentele suplimentare care încep cu `--`
    argv = [arg for arg in argv if not arg.startswith('--')]

    if len(argv) != 2:
        print('usage: mbox_parser.py [path_to_mbox]')
        # Într-un Jupyter Notebook, setați fișierul mbox explicit
        mbox_file = 'C:\\Users\\Here\\Desktop\\Disertatie-Final\\4. Cod\\thesis-phishing-email-detection-main\\phishing_dataset\\private-phishing4.mbox'  # Înlocuiți cu calea reală către fișierul mbox
    else:
        # Încărcați setările de mediu
        load_dotenv(verbose=True)

        mbox_file = argv[1]
        file_name = ntpath.basename(mbox_file).lower()
        # Sanitizați numele fișierului de export pentru a elimina caracterele nevalide
        export_file_name = re.sub(r'[<>:"/\\|?*]', '_', file_name) + ".csv"
        export_file = open(export_file_name, "wb")

        # Obțineți proprietarii mbox-ului
        owners = []
        if os.path.exists(".owners"):
            with open('.owners', 'r') as ownerlist:
                contents = ownerlist.read()
                owner_dict = ast.literal_eval(contents)
            # Găsiți proprietarii
            for owners_array_key in owner_dict:
                if owners_array_key in file_name:
                    for owner_key in owner_dict[owners_array_key]:
                        owners.append(owner_key)

        # Obțineți lista neagră a domeniilor
        blacklist_domains = []
        if os.path.exists(".blacklist"):
            with open('.blacklist', 'r') as blacklist:
                blacklist_domains = [domain.rstrip() for domain in blacklist.readlines()]

        # Creează CSV cu rândul de antet
        writer = csv.writer(export_file, encoding='utf-8')
        writer.writerow(["flagged", "date", "description", "from", "to", "cc", "subject", "content", "time (minutes)"])

        # Creează numărătoare de rânduri
        row_written = 0

        for email in mailbox.mbox(mbox_file):
            # Capturați conținutul implicit
            date = get_date(email, os.getenv("DATE_FORMAT"))
            sent_from = get_emails_clean(email["from"])
            sent_to = get_emails_clean(email["to"])
            cc = get_emails_clean(email["cc"])
            subject = re.sub('[\n\t\r]', ' -- ', str(email["subject"]))
            contents = get_content(email)

            # Aplicați reguli la conținutul implicit
            row = rules.apply_rules(date, sent_from, sent_to, cc, subject, contents, owners, blacklist_domains)

            # Scrieți rândul
            writer.writerow(row)
            row_written += 1

        # Raport
        report = "generated " + export_file_name + " for " + str(row_written) + " messages"
        report += " (" + str(rules.cant_convert_count) + " could not convert; "
        report += str(rules.blacklist_count) + " blacklisted)"
        print(report)

        export_file.close()
