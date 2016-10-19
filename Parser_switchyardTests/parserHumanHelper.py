

with open('data.txt', 'r') as myfile:
    data=myfile.read().split('\n')
    for k in data:
        print(k.lstrip())