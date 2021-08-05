import random

def generate_ID():
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

# print(generate_ID())
