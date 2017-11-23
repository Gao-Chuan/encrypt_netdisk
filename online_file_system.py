import getpass
import os
import sys  
from os.path import join,basename,isdir  


logo = """
 _   _                  
| \ | |                 
|  \| | ___  ___  _ __  
| . ` |/ _ \/ _ \| '_ \ 
| |\  |  __/ (_) | | | |
|_| \_|\___|\___/|_| |_|
                        
"""

guestwel = """
welcome to Neon file system!
you can:
1. register
2. log in

command:>>"""

userwel = """
1. logout
2. list your folder as tree
3. upload your file
4. download your file
5. cat your file

command:>>"""

def logout():
    print('good bye!')
    exit()

def login():
    print('login...')
    username = input('username:>>')
    pw = getpass.getpass('password:>>')
    if pw == username + '_pw':
        print('hello ', username, '!')
        return username
    else:
        print('error password or username')
        return ''

def regist():
    print('regist...')
    username = input('username:>>')
    if os.path.exists('./netdisk/' + username):
        print('username exist!')
        return ''
    else:
        os.makedirs('./netdisk/'+username)
    input('password:>>')
    print('hello ', username)
    return username

a, b = 0, 0

def tree(d,leval=0,pre=''):     
    global a,b   
    l=[i for i in os.listdir(d) if i[0]!='.']  
    for i,f in enumerate(l):  
        last= i==len(l)-1  
        s1="'" if last else '|'  
        s2=" " if last else '|'  
        print('{}{}--{}'.format(pre,s1,f))          
        t=join(d,f)  
        if os.path.isdir(t):  
            a+=1  
            tree(t,leval+1,'{}{}  '.format(pre,s2))              
        else:  
            b+=1
    
def list_(d=os.getcwd()):
    global a,b   
    a, b = 0, 0
    print(basename(d.rstrip(os.sep)))  
    tree(d)  
    print('\ntotal={}folders,{}files\n'.format(a,b))


def upload():
    print('')

def download(args):
    pass

def outsourced(args):
    pass

def cat(un, fn):
    path = './netdisk/'+un+'/' +fn
    print(path)
    if os.path.exists(path):
        with open(path) as fp:
            print(fp.read())
    else:
        print('file not exist!')

def main():
    # 绑定到一个io端口
    #提供服务

    print(logo)
    username = ''
    while True:
        if username == '':
            print()
            c = input(guestwel)

            if c == '2':
                username = login()
            elif c == '1':
                username = regist()
        else:
            c = input(userwel)
            if c == '1':
                logout()
            elif c == '2':
                list_('./netdisk/'+username)
            elif c == '3':
                pass
            elif c == '4':
                pass
            elif c == '5':
                filename = input('filename:>>')
                cat(username, filename)
        


if __name__ == '__main__':
    main()