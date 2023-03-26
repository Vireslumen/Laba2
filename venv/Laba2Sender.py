# Импорт необходимых модулей
import base64
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Определение функции для отправки писем
def send_email(is_new):
    # Определение путей к файлам и установка значений по умолчанию для уже существующих писем
    signature_path = "signature.txt"
    if(is_new):
        # Запрос информации у пользователя для нового письма
        sender_email = input("Введите свой email: ")
        sender_password = input("Введите свой пароль: ")
        recipient_email = input("Введите email на которую отправить письмо: ")
        subject = input("Введите тему письма: ")
        message_body = input("Введите текст письма: ")
        private_key_path = input("Введите путь к закрытому ключу: ")
    else:
        # Используем значения по умолчанию для тестирования
        sender_email = "****@yandex.ru"
        sender_password = "****"
        recipient_email = "****@yandex.ru"
        subject = "Test"
        message_body = "Hello, world!!!!!"
        private_key_path = "private_key.pem"

    # Загружаем закрытый ключ из файла с сертификатом
    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    # Преобразуем текст письма в байты
    message_data = message_body.encode()

    # Подписываем текст письма с использованием закрытого ключа
    signature = private_key.sign(message_data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    # Кодируем подпись в виде байтов base64
    signature_b64 = base64.b64encode(signature)
    with open(signature_path, 'wb') as signature_file:
        signature_file.write(signature_b64)

    # Собираем письмо
    message = MIMEMultipart()
    message['To'] = recipient_email
    message['From'] = sender_email
    message['Subject'] = subject

    # Добавляем текст письма
    body = MIMEText(message_body)
    message.attach(body)

    # Прикрепляем подпись к письму
    with open(signature_path, 'rb') as f:
        signature_part = MIMEApplication(f.read(), _subtype='signature')
        signature_part.add_header('Content-Disposition', 'attachment', filename=signature_path)
        message.attach(signature_part)

    # Подключаемся к серверу SMTP и отправляем письмо
    with smtplib.SMTP('smtp.yandex.ru', 587) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, message.as_string())

# Запуск функции с False для значений по умолчанию и True для ввода новых значений
send_email(True)