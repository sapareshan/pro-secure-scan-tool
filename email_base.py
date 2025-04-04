import smtplib
from email.mime.text import MIMEText

sender_email = "ayyanayyan00602@gmail.com" 
password = "jxcfalhcceciphwc"



def sendOtp(receiver_email, body,sub = 'OTP verifaction mail'):

    if not receiver_email or not body:
       print('Receiver or Body is not contain')
       return

    message = MIMEText(body, 'plain')
    message['Subject'] = sub
    message['From'] = sender_email
    message['To'] = receiver_email

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls() 
            server.login(sender_email, password) 
            server.send_message(message)
        print("Email sent successfully!")
    except Exception as e:
        print(f"An error occurred: {e}")
        