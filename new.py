# from pcapfile import savefile
import pyshark


# from scapy.all import *
# from scapy.layers.l2 import Dot1Q

def count_overlapping_substrings(haystack, needle):
    count = 0
    i = -1
    while True:
        i = haystack.find(needle, i + 1)
        if i == -1:
            return count
        count += 1

def main():
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
    filePCAP = str(input("Введите имя файла .pcap в рабочей папке:"))
    packets = pyshark.FileCapture('C:\\Users\\kgeny\\Desktop\\tcp\\filter.toss00.pcap', use_json=True, include_raw=True)
    b = 1
    s = ''
    while b:
        mainMenu = str(input("1)Проверка на STUN/TRUN;"
                             "2)Проверка на GRE;"
                             "3)Провека на GTP;"
                             "0)Выход"))
        if mainMenu == '1':
            stunFilter = ''
            for packet in packets:
                # print (str(packet))
                if "STUN" in str(packet.layers):
                    print('STUN присутствует в DUMP\n')
                    stunFilter = str(input("Нужен ли фильтр для STUN?"
                                           "1)Да"
                                           "0)Нет"))
                    break
            if stunFilter == '1':
                vlanBool = 1
                mplsBool = 1
                k = 0
                for packet in packets:
                    # print(k)
                    k += 1
                    if "VLAN" in str(packet) and vlanBool:
                        for i in range(count_overlapping_substrings(str(packet), 'VLAN')):
                            s += 'vlan and '
                        vlanBool = 0
                    if "MPLS" in str(packet) and mplsBool:
                        for i in range(count_overlapping_substrings(str(packet), 'MPLS')):
                            s += 'mpls and '
                        mplsBool = 0
                    # print(packet.get_raw_packet().hex())
                    # if str(packet.udp) == '17':
                    #     s += 'udp[' + str(strOut[0] - 20) + ':' + str(int(len(stunMagic) / 2)) + ']=0x' + str(
                    #         stunMagic) + '\n'
                    pkt = packet.get_raw_packet().hex()
                    ipIndex = str(pkt).find(stunMagic)
                    # print(ipIndex)
                    minIPIndex = ipIndex
                    if ipIndex != -1:
                        for ipH in ipHeads:
                            ipHeadIndex = str(pkt).find(ipH)
                            if minIPIndex > ipHeadIndex > 0:
                                minIPIndex = ipHeadIndex
                                minIP = ipH
                        if minIPIndex != ipIndex and (ipIndex - minIPIndex) / 2 > 0:
                            offset.append(
                                (int((ipIndex - minIPIndex) / 2), str(pkt)[minIPIndex + 18:minIPIndex + 20]))
                            k += 1
                tL = 0
                s += '('
                for strOut in set(offset):
                    if strOut[0] != 36:
                        if strOut[1] == '11':
                            s += 'udp[' + str(strOut[0] - 20) + ':' + str(int(len(stunMagic) / 2)) + ']=0x' + str(
                                stunMagic) + ' or '
                        elif strOut[1] == '01':
                            s += 'icmp[' + str(strOut[0] - 20) + ':' + str(int(len(stunMagic) / 2)) + ']=0x' + str(
                                stunMagic) + ' or '
                s = s[:-4]
                s = s + ')'
        elif mainMenu == '0':
            b = 0
    print(s)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
