# -*- coding: utf-8 -*-
"""
Created on Tue Jun 13 09:43:05 2017

@author: smaiorino & jfoy
Note: search-by-watchlist.py requires LR_Search.py to be in the same folder when run
Addidtionally, this script requires a modification to the Cb Response API function poll_status
see the document Live_Response_Mod.docx for further information

Runs in Python 3.6

"""

from cbapi.response.models import Binary
from cbapi.response import CbResponseAPI, Sensor
from cbapi.errors import TimeoutError, ObjectNotFoundError, ApiError, ServerError
from cbapi.response.live_response_api import LiveResponseError
from file_encryptor import convergence

import shutil
import csv
import os

       
def search():
    
    global watchlist, bin_file, api
    
    save_path = 'C:/Users/SMaiorino/Documents/My_Scripts/Master'
    f_name = os.path.join(save_path, 'Mal_Files_Found_{0}.csv'.format(watchlist))
    my_file = open(f_name,'w',newline='')
    writer = csv.writer(my_file)
    
    # Retrieve the necessary filenames and workstations by reading each csv file
    with open(os.path.join(save_path, 'vulnerable-names.csv'),'r') as n:
        names = n.readlines()

    with open(os.path.join(save_path, 'vulnerable-files.csv'), 'r') as f:
        files = f.readlines()
    
    print('\n---------------RESULTS---------------\n')
            
    for name in names:
        name = name.replace('\n', '')
        api = CbResponseAPI()
        try:
            sensor = api.select(Sensor).where('hostname:{0}'.format(name)).first()
            
            # Record Workstations with an Offline Sensor
            if sensor.status == 'Offline':
                writer.writerow([name, 'OFFLINE'])
                continue      
            
#            We use String manipulation for proper communication between the live response session and the 
#            format of each file / workstation. 
#            We only use 'bin_file' in the copy_encrypt_binary() function below.
#            
#            We then Copy the contents of the file on the current end point to a specified folder to a quarantee folder.
#            The file is then deleted from the current end point and we write the contents to a csv as:
#            
#            HOSTNAME            FILE FOUND ON COMPUTER (or OFFLINE)
#            
#            We then return to the top of loop and move on to the next end point in our list.
            
            # Start the live response session
            with sensor.lr_session() as session:
                for file in files:
                    bin_file = file.replace('\\','\\\\')
                    file = file.replace('\n', '')
                    try:
                        # Obtain the contents of each file
                        test_file = session.get_file(r'{0}'.format(file))
                        if test_file is not None:
                            copy_encrypt_binary()
                            session.delete_file(r'{0}'.format(file))
                            writer.writerow([name,file])
                            print('File: {0} \nComputer: {1} \n'.format(file,name))
                            continue               
                    except (TimeoutError, ObjectNotFoundError, LiveResponseError, 
                            ApiError, ServerError, AttributeError, TypeError):
                        pass
        except (TimeoutError):
            continue
        except (AttributeError):
            if sensor is None:
                continue
            break

        
    my_file.close()
    
    
# Copy Binary to a Local Directory and encrypt using convergent encryption
def copy_encrypt_binary():
    
    global bin_file, api
    save_path2 = 'C:/test_lr'
    b = api.select(Binary).where('observed_filename:{0}'.format(bin_file)).first()
    file_name = str(b.observed_filename).rsplit('\\', 1)[-1].replace("']",'')
    shutil.copyfileobj(b.file, open(os.path.join(save_path2, file_name), 'wb'))
    key = convergence.encrypt_file_inline("c:\\test_lr\\{0}".format(bin_file))
    return key

# Remove duplicate workstation names    
def remove_dupes():
    
        with open('vulnerable-names-dupes.csv','r') as n_in, \
         open('vulnerable-files-dupes.csv','r') as f_in, \
         open('vulnerable-names.csv','w') as n_out, \
         open('vulnerable-files.csv','w') as f_out:
             unique_names = set()
             unique_files = set()
             for name in n_in:
                 if name in unique_names:
                     continue
                 unique_names.add(name)
                 n_out.write(name)
             
             for file in f_in:
                 if file in unique_files:
                     continue
                 unique_files.add(file)
                 f_out.write(file)
                 
def main():
    
    global watchlist, cb
    
    cb = CbResponseAPI()

    vuln_names = open("vulnerable-names-dupes.csv", 'w', newline = '')
    write_names = csv.writer(vuln_names  )
    
    vuln_files = open('vulnerable-files-dupes.csv','w', newline = '')
    write_files = csv.writer(vuln_files)
    
    watchlist = input('Watchlist to Search Through: ')
    
    # NOTE: need to go into the Response Console and click 
    # on the WatchList of interest - the watchlist ordinal 
    # will appear in the URL field https://172.16.95.214:8443/#watchlist/190/?filterBy=all&sortBy=name
    # pass this ordinal as a command line parameter when invoking this script
    
    binary_query = cb.select(Binary).where("watchlist_{0}:*".format(watchlist))
    
    #find all instances of the binary watchlist hits including historical instances
    for binary in binary_query:
        for filename in binary.observed_filename:
            for endpoint in binary.endpoint:
                write_names.writerow([endpoint.split("|")[0]])
                write_files.writerow([filename])
                    
    vuln_names.close()
    vuln_files.close()
    
    remove_dupes()
    
    os.remove('vulnerable-names-dupes.csv')
    os.remove('vulnerable-files-dupes.csv')
    
    #call search() to clean the list of files by verifying their presence or absence on the end point
    search()
    
if __name__ == '__main__':
    main()

