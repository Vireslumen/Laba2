import imaplib
import email
import base64
import os
from dateutil.parser import parse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Определение функции для проверки подлинности письма
def signature_check(is_new):
    if (is_new):
        # Запрос информации у пользователя для работы приложения
        mail_username = input("Введите свой email: ")
        mail_password = input("Введите свой пароль: ")
        open_key_path = input("Введите путь к открытом ключу: ")
    else:
        # Используем значения по умолчанию для тестирования
        mail_username = '***@yandex.ru'
        mail_password = '****'
        open_key_path = 'open_key'

    # Определение данных для входа в почтовый ящик Yandex
    mail_host = 'imap.yandex.ru'
    mail_port = 993

    # Инициализация подключения к почтовому ящику
    mail = imaplib.IMAP4_SSL(mail_host, mail_port)
    mail.login(mail_username, mail_password)

    # Выбор папки входящих сообщений (inbox)
    mail.select('inbox')

    # Установка количества последних сообщений для получения
    num_recent_messages = 5

    # Поиск писем на основе критериев поиска
    status, email_ids = mail.search(None, 'ALL')
    email_ids = email_ids[0].split()[-num_recent_messages:]

    # Цикл по последним письмам и получение информации о них
    for index, email_id in enumerate(reversed(email_ids)):
        # Получение информации о письме по его ID
        status, email_data = mail.fetch(email_id, '(RFC822)')
        email_message = email.message_from_bytes(email_data[0][1])

        # Получение темы письма
        subject = email_message['subject']

        # Инициализация переменной для хранения тела письма
        body = ''

        # Проверка, является ли письмо многокомпонентным, и получение текстового содержимого, если оно доступно
        if email_message.is_multipart():
            for part in email_message.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain':
                    body = part.get_payload(decode=True).decode()
        else:
            body = email_message.get_payload(decode=True).decode()

        # Получение даты письма и форматирование
        date_str = email_message['date']
        date_obj = parse(date_str)
        date_formatted = date_obj.strftime('%Y-%m-%d %H:%M:%S')

        # Получение имён файлов вложений
        attachments = []
        for part in email_message.walk():
            filename = part.get_filename()
            if filename:
                attachments.append(filename)

        # Вывод информации о письме
        print(f'\nEmail {index+1}')
        print(f'Тема: {subject}')
        print(f'Дата: {date_formatted}')
        print(f'Сообщение: {body}')
        print(f'Прикрепленные файлы: {attachments}')
        print('--------------------------')

    # Выбор письма для загрузки вложения и извлечения информации о нём
    selected_email_num = num_recent_messages - int(input('Введите номер письма для загрузки: ')) # получение от пользователя номера письма
    email_id = email_ids[selected_email_num]

    status, email_data = mail.fetch(email_id, '(RFC822)')
    email_message = email.message_from_bytes(email_data[0][1])

    # Создание папки для сохранения загруженных файлов письма
    output_folder = f'email_{email_id}'
    if not os.path.exists(output_folder):
        os.mkdir(output_folder)

    # Инициализация переменной для хранения тела письма
    body = ''
    if email_message.is_multipart():
        # Цикл по компонентам письма и получение текстового содержимого, если оно доступно
        for part in email_message.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain':
                body = part.get_payload(decode=True).decode()
    else:
        body = email_message.get_payload(decode=True).decode()

    # Получение файлов вложений и сохранение их в папке
    data = body.encode() # кодирование текста письма
    print("Текст сообщения: "+body)
    for part in email_message.walk():
        filename = part.get_filename()
        if filename:
            # Определение пути к вложению и сохранение его
            filepath = os.path.join(output_folder, filename)
            with open(filepath, 'wb') as f:
                f.write(part.get_payload(decode=True))

    # Проверка подписи письма, если она существует
    signature_file = os.path.join(output_folder,'signature.txt')
    if os.path.exists(signature_file):
        with open(signature_file, 'rb') as signature_file:
            signature_b64 = signature_file.read()
        with open('certificate.pem', 'rb') as cert_file:
            cert_data = cert_file.read()

        # Загрузка открытого ключа из сертификата
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        public_key = cert.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(open_key_path, 'rb') as key_file:
            public_key = serialization.load_pem_public_key(public_key_pem)

        # Проверка подписи письма
        signature = base64.b64decode(signature_b64)
        try:
            public_key.verify(signature, data,
                              padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                              hashes.SHA256())
            print("Подпись верна.")
        except:
            print("Подпись недействительна.")
    else:
        print('Письмо не подписано')

    # Закрытие подключения к почтовому ящику
    mail.close()
    mail.logout()

# Запуск функции с False для значений по умолчанию и True для ввода новых значений
signature_check(True)