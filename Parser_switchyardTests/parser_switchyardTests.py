

with open('multiData.txt', 'r') as myMfile:
    mData=myMfile.read().split('Expected')
    mData.pop(0)
    n=0
    for mK in mData:
        n+=1
        print()
        print('#{}'.format(n))
        pos = mK.rfind('bytes) on eth')
        if(pos == -1):
            pos = mK.rfind('bytes) out eth') + len('bytes) out eth')
        else:
            pos+=+ len('bytes) on eth')

        mK = mK.lstrip()[:pos]
        #print(mK)

        i=0
        eEvent = ''
        sMac=''
        dMac=''
        sIP = ''
        dIP = ''
        concernInterface = ''
        macList = []
        IPList =[]
        stageFlag = 0
        changeFlagMac = 1
        changeFlagIP = 1
        for k in mK.split('\n'):
            k = k.lstrip()
            i+=1
            j = (i-1)%3
            if(i==1):
                if( 'send_packet' in k.lstrip()):
                    eEvent = 'send_packet(s)'
                elif('recv_packet' in k.lstrip()):
                    eEvent = 'recv_packet'

            if(j==1):
                macPair = k.split(' ',1)
                sMac = macPair[0].split('->')[0]
                dMac = macPair[0].split('->')[1]
                if(len(macList) > 0):
                    if((sMac,dMac) != macList[0]):
                        macList.pop()
                        macList.append((sMac,dMac))
                        changeFlagMac = 1

                else:
                    macList.append((sMac, dMac))
            elif(j==2):
                IPPair = k.split(' ', 1)
                sIP = IPPair[0].split('->')[0]
                dIP = IPPair[0].split('->')[1]
                if (len(IPList) > 0):
                    if ((sIP, dIP) != IPList[0]):
                        IPList.pop()
                        IPList.append((sIP, dIP))
                        changeFlagIP = 1
                else:
                    IPList.append((sIP, dIP))

            elif(j==0 and i!=1):
                sPos = k.find('eth')
                ePos = k.find(' ',sPos)
                if(ePos == -1):
                    concernInterface = k[sPos:]
                else:
                    concernInterface = k[sPos:ePos]
                stageFlag = 1

            if(stageFlag == 1):
                if(len(macList) > 0 and changeFlagIP == 1):
                    print('testpkt = mk_pkt("{}", "{}", "{}", "{}")'.format(macList[0][0],macList[0][1],IPList[0][0],IPList[0][1]))
                    changeFlagIP = 0

                if(eEvent == 'send_packet(s)'):
                    print('s.expect(PacketOutputEvent("{}", testpkt, display=Ethernet), "Frame sent out on {} outbound for {}")'.format(concernInterface, concernInterface, macList[0][1]))
                elif(eEvent == 'recv_packet'):
                    print('s.expect(PacketInputEvent("{}", testpkt, display=Ethernet), "An ethernet frame from {} to {} arrives on {}")'.format(concernInterface,macList[0][0],macList[0][1],concernInterface))
                stageFlag = 0

            #print(k)

            'testpkt = mk_pkt("30:00:00:00:00:01", "30:00:00:00:00:02", "172.16.42.1", "172.16.42.2")'
            's.expect(PacketInputEvent("eth0", testpkt, display=Ethernet), "An ethernet frame from 1 to 2 arrives on eth0")'
            's.expect(PacketOutputEvent("eth1", testpkt, display=Ethernet), "Frame sent out on eth1 outbound for 2")'