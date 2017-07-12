# -*- coding: utf-8 -*-
"""
Created on Tue Jun  6 13:37:07 2017

@author: smaiorino
"""

from cbapi.protection import CbProtectionAPI, Computer
import csv
import os.path

def prot_win_servers():
    # Initialize CB Protect API and query parameters
    api = CbProtectionAPI()
    query = api.select(Computer)
    query = query.sort('name ASC')
    
    # Set attributes for csv file
    save_path = 'C:/Users/SMaiorino/Documents/My_Scripts/Master/Computer Lists'
    f_name = os.path.join(save_path, 'List_winServers_Protect.csv')
    file = open(f_name, 'w', newline = '')
    f_write = csv.writer(file)
    
    # Iterate through each computer and write to the csv file
    # with desired attributes
    

    for comp in query:
        if comp.deleted is False \
        and 'Server' in comp.policyName and 'Windows' in comp.osName:
            names = comp.name
            # Ignore the 'NBME\' in the beginning of each name
            if names.startswith("NBME\\"):
                names = names[5:]
            f_write.writerow([names])
                          
    file.close()
    
if __name__ == '__main__':
    prot_win_servers()