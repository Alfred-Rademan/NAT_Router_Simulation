import random
import string


def gen_ip():
    p_1 = random.randint(0, 100)
    p_2 = random.randint(0,100)
    p_3 = random.randint(0,100)
    p_4 = random.randint(0,100)
    return str(p_1) +'.'+str(p_2)+'.'+str(p_3)+'.'+str(p_4)
def gen_mac():
    l = ""
    for i in range (0,12 ):
        l = l+random.choice(string.ascii_uppercase + string.digits)
        if(i % 2 == 1 and i != 11):
            l = l +'.'
            
    return l
    

for i in range(0,200):
    print(gen_ip())
    print(gen_mac())
