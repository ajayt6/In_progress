

a = {}

a[1] = "a"
a[2] = "b"
a[3] = "c"
a[4] = "d"

for k in a:
    print(a[k])

dict1 = {str(i):None for i in range(10000)}
dict2 = {}
dict2.update(dict1)

print(dict1 == dict2)
print(dict1.keys() == dict2.keys())