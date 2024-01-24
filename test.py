message_1 = input('Введите первое сообщение: ')
message_2 = input('Введите второе сообщение: ')

l_message_1 = list(message_1)
l_message_2 = list(message_2)

count_1 = l_message_1.count('!') + l_message_1.count('?')
count_2 = l_message_2.count('!') + l_message_2.count('?')

if count_1 > count_2:
    print(message_1, message_2)
elif count_2 > count_1:
    print(message_2, message_1)
else:
    print('Ой')