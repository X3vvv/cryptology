'''
All kinds of password security strength rules.
reference: https://zhuanlan.zhihu.com/p/25545606
'''


def simpleRule(pw: str):
    '''
    Return true if no less than 2 rules are passed.
    Prompt accordingly otherwise.

    Rule 1: len >= 8, has number(s) & alphabet(s)
    Rule 2: has special simbol(s)
    Rule 3: has capital alphabet(s)
    '''
    r1, r2, r3 = False, False, False

    # Rule 1: len >= 8, has number(s) & alphabet(s)
    if len(pw) >= 8:
        hasNum, hasAlpha = False, False
        for c in pw:
            if c.isalpha():
                hasAlpha = True
            if c.isnumeric():
                hasNum = True
        if hasNum and hasAlpha:
            r1 = True

    # Rule 2: has special simbol(s)
    if not pw.isalnum():
        r2 = True

    # Rule 3: has capital alphabet(s)
    for c in pw:
        if c.isupper():
            r3 = True

    # passed
    if r1 and r2 and r3:
        return True
    if (r1 and r2) or (r2 and r3) or (r1 and r3):
        return True

    # not pass and prompt accordingly
    if r1:
        # prompt rule 2
        print("Please contain special symbol(s).")
    elif r2:
        # prompt rule 1
        print("Password should has at least 8 characters with both numbers and letters.")
    elif r3:
        # prompt rule 1
        print("Password should has at least 8 characters with both numbers and letters.")
    return False


def normalRule(pw: str):
    '''
    Standards:
    1. Password length:
        5  pt: <= 4 char
        10 pt: 4 ~ 7 char
        25 pt: >= 8 char
    2. Alphabet:
        0  pt: no alphabet
        10 pt: single upper/lower case
        20 pt: mixed upper/lower case
    3. Number:
        0  pt: no number
        10 pt: 1 or 2 number(s)
        20 pt: >= 3 numbers
    4. Symbol:
        0  pt: 0 symbol
        10 pt: 1 symbol
        25 pt: >= 1 symbol
    5. Reward:
        2 pt: has both alphabet and number
        3 pt: has alphabet, number, and symbol
        5 pt: has upper & lower case alphabet, number, and symbol

    Rule:
    >= 90: very secure
    >= 80: secure
    >= 70: very strong
    >= 60: strong
    >= 50 average
    >= 25: weak
    >=  0: very weak
    '''

    pt = 0

    # 1. Password length:
    #     5  pt: <= 4 char
    #     10 pt: 4 ~ 7 char
    #     25 pt: >= 8 char
    if len(pw) <= 4:
        pt += 5
    elif len(pw) <= 7:
        pt += 10
    else:
        pt += 25

    # 2. Alphabet:
    #     0  pt: no alphabet
    #     10 pt: single upper/lower case
    #     20 pt: mixed upper/lower case
    hasLower, hasUpper = False, False
    for c in pw:
        if c.islower():
            hasLower = True
        if c.isupper():
            hasUpper = True
    if hasLower and hasUpper:
        pt += 20
    elif hasLower or hasUpper:
        pt += 10

    # 3. Number:
    #     0  pt: no number
    #     10 pt: 1 or 2 number(s)
    #     20 pt: >= 3 numbers
    numN = 0  # number of numbers
    for c in pw:
        if c.isnumeric():
            numN += 1
    if numN >= 3:
        pt += 20
    elif numN > 0:
        pt += 10

    # 4. Symbol:
    #     0  pt: 0 symbol
    #     10 pt: 1 symbol
    #     25 pt: > 1 symbol
    symN = 0
    for c in pw:
        if not c.isalnum():
            symN += 1
    if symN > 1:
        pt += 25
    elif symN > 0:
        pt += 10

    # 5. Reward:
    #     2 pt: has both alphabet and number
    #     3 pt: has alphabet, number, and symbol
    #     5 pt: has upper & lower case alphabet, number, and symbol
    if hasLower and hasUpper and numN > 0 and symN > 0:
        pt += 5
    elif (hasLower or hasUpper) and numN > 0 and symN > 0:
        pt += 3
    elif (hasLower or hasUpper) and numN > 0:
        pt += 2

    # Rule:
    # >= 90: very secure
    # >= 80: secure
    # >= 70: very strong
    # >= 60: strong
    # >= 50 average
    # >= 25: weak
    # >=  0: very weak
    if pt >= 90:
        print("Very secure")
    elif pt >= 80:
        print("Secure")
    elif pt >= 70:
        print("Very strong")
    elif pt >= 60:
        print("Strong")
    elif pt >= 50:
        print("Average")
    elif pt >= 25:
        print("Weak")
    else:
        print("Very weak")

    return


def profRule(pw: str):
    '''
    pt = (hasPassesBasePasswordRules) * 70 +
        (charNum - 8) * 4 +
        (alphaNum - upperNum) * (alphaNum - lowerNum) * 2 -
        (consecutiveRepeatCharNum) * 2 -
        (consecutiveNumberNum - 3) * 1 -
        (consecutiveAlphaNum - 3) * 1 -
        (has3orMoreSequentialNumber) * 3 -
        (has3orMoreSequentialAlpha) * 3

    pt rule: 
    >= 80: Strong
    >= 60: Medium
    <  60: Weak
    '''


def highProfRule(pw: str):
    '''
    分数区间：

    60＞x＞0：未达标准

    70＞x≥60：警告

    80＞x≥70：已达标准

    x≥80：优秀(100为上限)

    符号说明：

    --> Flat:均一的 加/扣分 比例。

    --> Incr：出现次数越多，加/扣分 比例越大。

    --> Cond：根据增加的字元数调整
    加/扣分 比例。

    --> n：出现次数。

    --> len：密码字串长度。

    积分说明：

    · 增加字符的变化能提高分数。

    · 最后的分数为加分项目和减分项目的总和。

    · 分数的范围为0~100分。

    · 分数不需达到最低字元即可计算。

    规则说明：

    --> 密码最低要求8字元

    --> 最少符合下列4项中3项规则:- 大写英文字元- 小写英文字元- 数字字元- 符号字元

    l 加分项目

    --> 密码字数/Flat/+(n*4)

    --> 大写英文字母/Cond或Incr/+((len-n)*2)

    --> 小写英文字母/Cond或Incr/+((len-n)*2)

    --> 数字字元/Cond/+(n*4)

    --> 符号字元/Flat/+(n*6)

    --> 密码中间穿插数字或符号字元/Flat/+(n*2)

    --> 已达到密码最低要求项目/Flat/+(n*2)

    l 扣分项目

    --> 只有英文字元/Flat/-n

    --> 只有数字字元/Flat/-n

    --> 重复字元(Case Insensitive)/Incr/-(n(n-1))

    --> 连续英文大写字元/Flat/-(n*2)

    --> 连续英文小写字元/Flat/-(n*2)

    --> 连续数字字元/Flat/-(n*2)

    --> 连续字母超过三个(如abc, def)/Flat/-(n*3)

    --> 连续数字超过三个(如123,234)/Flat/-(n*3)

    示例：

    密码：Aa123 分数：43分 强度：未达标准

    密码：Aa12L3 分数：64分 强度：警告

    reference: https://zhuanlan.zhihu.com/p/25545606
    '''


def hashRule(pw: str):
    '''
    Exclude passwords in the rainbow table.
    reference: https://zhuanlan.zhihu.com/p/25545606
    '''
