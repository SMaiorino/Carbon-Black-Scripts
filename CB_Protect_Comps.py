# -*- coding: utf-8 -*-
"""
Created on Thur Apr 13 01:12:40 2017

@author: smaiorino
"""
# Creates a 'csv' file called 'List_Comps' which lists each computer 
# that exists within the CB Protect server

from cbapi.protection import CbProtectionAPI, Computer
import csv
import os.path

def cbProtect():
    # Initialize CB Protect API and query parameters
    api = CbProtectionAPI()
    query = api.select(Computer)
    query = query.sort('name ASC')
    
    # Set attributes for csv file
    save_path = 'C:/Users/SMaiorino/Documents/My_Scripts/Master/Computer Lists'
    f_name = os.path.join(save_path, 'List_Comps_Protect.csv')
    file = open(f_name, 'w', newline = '')
    f_write = csv.writer(file)
    
    # Iterate through each computer and write to the csv file
    # with desired attributes
    

    for comp in query:
        if comp.deleted is False and 'Workstation' in comp.policyName \
        and not 'Server' in comp.policyName and 'Windows' in comp.osName \
        and comp.enforcementLevel == 20:
            names = comp.name
            last_date = str(comp.lastPollDate)[0:10]
            # Ignore the 'NBME\' in the beginning of each name
            if names.startswith("NBME\\"):
                names = names[5:]
            f_write.writerow([names])
                          
    file.close()
    
if __name__ == '__main__':
    cbProtect()

#               LIST OF ATTRIBUTES

########---------------------------------------------------------##########

   
#           last_conn = comp.lastPollDate
#           ip_addr = comp.ipAddress
#           policy = comp.policyName
#           comp_ID = comp.id
#           enforce_lvl = comp.enforcementLevel
