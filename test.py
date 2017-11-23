#!/usr/bin/env python3  
import os  
import sys  
from os.path import join,basename,isdir  
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
    
def main(d=os.getcwd()):                
    print(basename(d.rstrip(os.sep)))  
    tree(d)  
    print('\ntotal={}folders,{}files\n'.format(a,b)) 
      
if __name__=='__main__':  
    a,b=0,0     #a，b分别为文件夹总数和文件总数  
    if len(sys.argv)<2:  
        main()  
    else:  
        if isdir(sys.argv[1]):  
            main(sys.argv[1])  
        else:  
            print(sys.argv[1],'is not a directory')