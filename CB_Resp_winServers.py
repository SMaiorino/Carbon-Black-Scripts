# -*- coding: utf-8 -*-
"""
Created on Tue Jun  6 13:41:10 2017

@author: smaiorino
"""
from cbapi.response import CbResponseAPI
from cbapi.response.models import Sensor
import csv
import os.path


def resp_win_servers():
    # Set attributes for csv file
    save_path = 'C:/Users/SMaiorino/Documents/My_Scripts/Master/Computer Lists'
    f_name = os.path.join(save_path, 'List_winServers_Response.csv')
    file = open(f_name, 'w', newline = '')
    f_write = csv.writer(file)
    #f_write.writerow(['NAME'])
    
    # Initialize API var and query parameters
    api = CbResponseAPI()
    query = "ip:172"
    sensor = api.select(Sensor).where(query)
    
    # Iterate through each object the sensor reads and
    # output the name of each workstation in response that
    # is currently installed.
    for obj in sensor:
        names = obj.hostname
        os_name = obj.os_environment_display_string
        status = obj.status
        uninstall = obj.uninstall
        uninstalled = obj.uninstalled
        group = obj.group_id
        if 'Server' in os_name and 'Windows' in os_name \
        and uninstall == False and uninstalled != True \
        and not 'Uninstall' in status and group != 12:
            f_write.writerow([names])
    
    file.close()
    
    # Re-open the file to sort the names in alphabetically 
    # ascending order
    new_file = csv.reader(open(os.path.join(save_path, 'List_winServers_Response.csv')))
    sorted_file = sorted(new_file)
      
    # Re-write the sorted names into the file  
    with open(os.path.join(save_path, 'List_winServers_Response.csv'), 'w', newline = '') as f:
        f_write = csv.writer(f)
        for row in sorted_file:
            f_write.writerow(row)
            
if __name__ == '__main__':
    resp_win_servers()   