import ccard,random
from datetime import date
from faker import Faker
fake = Faker()

def generate_ID():
    '''create a fake israel id'''
    n = str(random.randint(20000000, 39999999))
    # print(n)
    # print(str(n1))
    number = 0
    for i in range(0, 8):
        if not (i % 2):
            number += int(n[i])
        else:
            temp = (int(n[i]) * 2)
            # test = temp %10 + (temp // 10)
            number += temp % 10 + (temp // 10)
            # print(int(n[i]),temp, temp%10, (temp // 10),test)
    # print(number)
    # number = 10
    if number % 10 == 0:
        return (f"{n}0")
    else:
        return (f"{n}{((number // 10 + 1) * 10) - number}")

def email_fake(name):
    '''create a fake email '''
    if name:
        return(name.replace(" ", "")+"@gmail.com")
    else:
        return(fake.name().replace(" ", "")+"@gmail.com")

def card(num=0):
    '''create a fake number for credit card '''
    if num ==4:
        num= random.randint(1,3)
    if 1 == num:
        return ccard.visa()
    if 2 == num:
        return ccard.mastercard()
    if 3 == num:
        return ccard.americanexpress()
    else:
        print("Enter number:\n\t1 for visa\n "
              "\t2 for mastercard\n "
              "\t3 for americanexpress\n "
              "\t4 for random card")
        return (0)

def phone_number( num=1 ):
    '''create a fake israel phone number'''
    if num == 1:
        return(f"+972{str(random.randint(500000000, 599999999))}")
    elif num == 2:
        return(f"0{str(random.randint(500000000, 599999999))}")
    elif num == 3:
        return (f"{str(random.randint(500000000, 599999999))}")
    else:
        print("Enter 1 for prefix 972\n2 for prifix 0\n3 for  none")
def fake_date():
    month=f"{str(random.randint(1, 12))}"
    year=f"{date.today().year + random.randint(1, 9)}"
    return (f"{month}/{year}")
def cve():
    '''create a CVE for credit card '''
    return(str(random.randint(000, 999)))

def fake_identity():
    print("ID:"+generate_ID(),end="\n")
    name=fake.name()
    print(f"Name:{name}",end="\n")
    print(f"Email:{email_fake(name)}",end="\n")
    print(f"Credit card:{card(4)}",end="\n")
    print("CVE:"+cve(),end="\n")
    print("Date:"+fake_date(),end="\n")
    print("Phone number:"+phone_number(),end="\n")

fake_identity()
