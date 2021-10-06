from pcapfile import savefile
from scapy.all import *
from scapy.layers.l2 import Dot1Q

k = 0
ipHeads = [
    '4500',
    '4520',
    '4528',
    '4530',
    '4538',
    '4540',
    '4548',
    '4550',
    '4558',
    '4560',
    '4568',
    '4570',
    '4578',
    '4580',
    '4588',
    '4590',
    '4598',
    '45a0',
    '45c0',
    '45e0',
    '45b8']
offset = []
stunMagic = '2112a442'
while True:
    filePCAP = str(input("Введите имя файла .pcap в рабочей папке:"))
    file = open('C:\\Users\\kgeny\\Desktop\\tcp\\filter.toss00.pcap', 'rb')
    pcapfile = savefile.load_savefile(file, verbose=True)
    capfile = rdpcap('C:\\Users\\kgeny\\Desktop\\tcp\\filter.toss00.pcap')
    mainMenu = str(input("1)Проверка на STUN/TRUN;"
                         "2)Проверка на GRE;"
                         "3)Провека на GTP;"))
    if mainMenu == '1':
        s = ''
        for i in range(len(pcapfile.packets)):
            # print(capfile[i].show(dump=True))
            pkt = pcapfile.packets[i]
            ipIndex = str(pkt).find(stunMagic)
            minIPIndex = ipIndex
            if ipIndex != -1:
                for ipH in ipHeads:
                    ipHeadIndex = str(pkt).find(ipH)
                    if minIPIndex > ipHeadIndex > 0:
                        minIPIndex = ipHeadIndex
                        minIP = ipH
                        j = 1
                        k = 0
                        b = True
                        while b:
                            try:
                                var = capfile[i][Dot1Q:j].vlan
                                if capfile[i][Dot1Q:j].type == 34887:
                                    k += 1
                                j += 1
                            except:
                                b = False
                if minIPIndex != ipIndex and (ipIndex - minIPIndex) / 2 > 0:
                    offset.append(
                        (int((ipIndex - minIPIndex) / 2), str(pkt)[minIPIndex + 18:minIPIndex + 20], j - 1, k))
                    k += 1
        s = 'STUN\n'
        for strOut in set(offset):
            if strOut[0] != 36:
                if strOut[2] > 0:
                    for j in range(strOut[2]):
                        s += 'vlan and '
                if strOut[3] > 0:
                    for j in range(strOut[3]):
                        s += 'mpls and '
                if strOut[1] == '11':
                    s += 'udp[' + str(strOut[0] - 20) + ':' + str(int(len(stunMagic) / 2)) + ']=0x' + str(
                        stunMagic) + '\n'
                elif strOut[1] == '01':
                    s += 'icmp[' + str(strOut[0] - 20) + ':' + str(int(len(stunMagic) / 2)) + ']=0x' + str(
                        stunMagic) + '\n'
        print(s)
    while True:
        hexOrDec = str(input("Выберите формат ввода запроса:"
                             "\n1)dec;"
                             "\n2)hex;\n"))
        if hexOrDec == '2':
            ipReq = str(input("Введите 1, 2 или 4 байта:"))
            if len(ipReq) == 2 or len(ipReq) == 4 or len(ipReq) == 8:
                break
            else:
                print("Неверный формат ввода!")
        elif hexOrDec == '1':
            ipReq = str(input("Введите ip адрес:"))
            a = ipReq.split('.')
            b = False
            if len(a) == 4:
                for x in a:
                    if x.isdigit():
                        i = int(x)
                        if 0 < i < 255:
                            b = True
                        else:
                            b = False
                            break
                    else:
                        b = False
                        break
            else:
                b = False
                break
            if b:
                s = ''
                for st in ipReq.split('.'):
                    s += str(hex(int(st)))[2:]
                ipReq = s
                break
            else:
                print("Неверный формат ввода!")
    for i in range(len(pcapfile.packets) - 1):
        pkt = pcapfile.packets[i]
        ipIndex = str(pkt).find(ipReq)
        minIPIndex = ipIndex
        if ipIndex != -1:
            for ipH in ipHeads:
                ipHeadIndex = str(pkt).find(ipH)
                if minIPIndex > ipHeadIndex > 0:
                    minIPIndex = ipHeadIndex
                    minIP = ipH
            if minIPIndex != ipIndex and (ipIndex - minIPIndex) / 2 > 0:
                '''print(i)
                print(str(pkt))
                print(str(pkt)[minIPIndex + 18:minIPIndex + 20])
                print("нашел", minIP, "разность", (ipIndex - minIPIndex) / 2)'''
                offset.append((int((ipIndex - minIPIndex) / 2), str(pkt)[minIPIndex + 18:minIPIndex + 20]))
                k += 1
    # print(set(offset))
    # print(len(set(offset)))
    for strOut in set(offset):
        if strOut[0] != 36:
            s = 'ip[' + str(strOut[0]) + ':' + str(int(len(ipReq) / 2)) + ']=0x' + str(ipReq)
            if strOut[1] == '11':
                s += ' или udp[' + str(strOut[0] - 20) + ':' + str(int(len(ipReq) / 2)) + ']=0x' + str(ipReq)
            elif strOut[1] == '01':
                s += ' или icmp[' + str(strOut[0] - 20) + ':' + str(int(len(ipReq) / 2)) + ']=0x' + str(ipReq)
            elif strOut[1] == '06':
                s += ' или tcp[' + str(strOut[0] - 20) + ':' + str(int(len(ipReq) / 2)) + ']=0x' + str(ipReq)
            print(s)
    break
    '''except:
        print("Ошибка!!!Файл не найден, введите заново!")'''
