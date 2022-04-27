def str2bit(s:str)->str:
    '''String to ASCII bit (8-bits/character).'''
    res = ''
    for c in s:
        ascii=format(ord(c),'08b')
        res += ascii
        # print(f"{c}: {ascii}")
    print(s, res)

if __name__ == "__main__":
    str2bit("zewenpanyy")
    str2bit("polyucomputing")