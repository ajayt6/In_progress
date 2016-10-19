

with open('multiData.txt', 'r') as myMfile:
    mData=myMfile.read().split('Expected')
    mData.pop(0)
    for mK in mData:
        pos = mK.rfind('bytes) on eth')
        if(pos == -1):
            pos = mK.rfind('bytes) out eth') + len('bytes) out eth')
        else:
            pos+=+ len('bytes) on eth')
        print(mK.lstrip()[:pos])
        #print(k.lstrip())