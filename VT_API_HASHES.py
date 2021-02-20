from pip._vendor import requests
import csv
import json
import time

mylist=[]
count=0
url = 'https://www.virustotal.com/vtapi/v2/file/report'

with open('sample.csv','r',newline='') as f:
    reader =csv.reader(f,delimiter=',')
    for row in reader:
        mylist.append(row)

with open('vtresults.csv','w',newline='') as d:
        Writer=csv.writer(d,delimiter=',')
        Writer.writerow(['HASHES','Detections'])     
        for row_ in mylist:

            while True:

                if count <=3:
                    params = {'apikey':'API_KEY', 'resource':row_}
                    response = requests.get(url, params=params)

                    if(response.status_code == 200):
                        json_data=json.loads(response.text)
                        check=json_data['response_code']                   #to check if the hash is present or not

                        if check ==0:                                       #0 means absent
                            Writer.writerow([row_[0],'Unknown hash '])

                        elif check !=0:                                     #not 0 means present 

                            we=str(json_data['positives']) + '/' + str(json_data['total'])
                            Writer.writerow([row_[0],we])

                        count=count+1

                        if count==4:
                            print('Limitation exceeded, Please wait 1 minute for the next 4 queries :')
                            time.sleep(65)
                            count=0

                        break

                    elif(response.status_code != 200):
                        time.sleep(10)
        print('Completed , Thanks for you time :)')           

