import smtplib

def t(rcpt):
    try:
        s = smtplib.SMTP("192.168.12.16", 25, timeout=12)
        code, msg = s.ehlo("cem.master01")
        print("EHLO caps:", msg.split()[:8])
        f = s.sendmail("ecollect@sidianbank.co.ke", [rcpt],
            "Subject: CEM relay test via 192.168.12.16\r\n\r\nRelay test from CEM via 192.168.12.16.\r\n")
        print(rcpt, "-> ACCEPTED, failures:", f)
        s.quit()
    except Exception as ex:
        print(rcpt, "-> FAILED:", repr(ex))

t("ecollect@sidianbank.co.ke")
t("kevin.miguta@intelligeninfosys.com")
