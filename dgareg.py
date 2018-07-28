#!/usr/bin/env python



import csv
import pickle

#
#last updated 13.10.2015
#
#by Soeren Fischer for "Malware Bootcamp 2015" - Rheinische-Friedrich-Wilhelms Universitaet Bonn
#


class CharCount(dict):
	def __getitem__(self, item):
        	try:
            		return dict.__getitem__(self, item)
        	except KeyError:
            		value = self[item] = 0
        	return value

class FreqCounter(dict):


	def __init__(self,*args,**kargs):
      		self.ignorechars = """\n\t\r~@#%^&*"'/\-+<>{}|$!:()[];?,="""	
      		
      		

  	def __getitem__(self, item):
      		try:
          		return dict.__getitem__(self, item)
      		except KeyError:
          		value = self[item] = CharCount()
      		return value

  	def freq_str(self,line,weight=1):					#weight could be used to tweak rating (short domains e.g.)
      										
      		wordcount=0
      		
          	line=line.lower()						#all lower case
      		
		for char in range(len(line)-1):					#run through whole string
          		if line[char] in self.ignorechars or line[char+1] in self.ignorechars:
          	    		continue					#one of ignorechars -> skip
          		if line[char+1] in self[line[char]]:
              			self[line[char]][line[char+1]]=self[line[char]][line[char+1]]+(1*weight)	#pair was seen add 1 to prob
          		else:							
              			self[line[char]][line[char+1]]=weight		#new pair -> init prob
      		return wordcount						

	



	def probability(self,string,max_prob=40):
     
		probs=[]
		for pos,ch in enumerate(string[:-1]):
	        	if not ch in self.ignorechars and not string[pos+1] in self.ignorechars:	#treated chr and following not ignorechars
				probs.append(self._probability(ch,string[pos+1],max_prob))		#append bigram to probs with prob
		if len(probs)==0:									#no bigram rated
        		return 0
		return sum(probs) / len(probs)								

  	def _probability(self,top,sub,max_prob=40):
      		
      		
       		top = top.lower()								#lower case again
       		sub = sub.lower()

      		if not self.has_key(top):							#no freq table for top 			
        		  return 0
      		all_letter_count = sum(self[top].values())					 
      		char2_count = 0

      		if self[top].has_key(sub):							#top has freq table to sub
        		  char2_count = self[top][sub]						#get rating from matrix
      		probab = float(char2_count)/float(all_letter_count)*100				#probab = prob of bigram = bigram occured / all chr tops has keys for
      	
		if probab > max_prob:
        		  probab = max_prob
      		return probab



             


with open('anonymized_dns_feed.csv', 'r') as csvfile:

	
	print 'Creating frequency table...'

        lib = FreqCounter()
        
	lib.freq_str(open("freqdicts/top1m.txt").read())		#filling freq-table with data retrieved vom analysing .txt(s)
	lib.freq_str(open("freqdicts/top1k.txt").read())
	lib.freq_str(open("freqdicts/top10k.txt").read())

	lib.freq_str(open("freqdicts/cthulhu.txt").read())       
        lib.freq_str(open("freqdicts/e_zann.txt").read())
	lib.freq_str(open("freqdicts/mountains.txt").read())
	lib.freq_str(open("freqdicts/20kmiles.txt").read())       

	print 'done'     

	print 'Importing csv...'

	fieldnames = ['timestamp','anonymized_hash','request','response','rating']	#adding field "rating"
        reader = csv.DictReader(csvfile, fieldnames=fieldnames)
        
	prob = 0
        container = []									#for saving domains for later use
	dgadomains = []									#generated domains
	infected = []									#infected users
        


	print 'done'
	


	threshold  = float(raw_input('Max rating for generated domains? (5 - 7 recommended) '))
	#threshold = 5
	

	nxthreshold = float(raw_input('Max rating for deeper look in NXDomains? (8 - 12 recommended) '))
	#nxthreshold = 10 
	

	noise  = float(raw_input('Max rating for noise? (0.5 recommended)'))
	#noise = 0.5
	

	print 'Building alexa-database...'
	
	
	alexaset = []
	with open('top-1mk.csv', 'r') as alexa:
		fields = ['count','domain']
        	alexalist = csv.DictReader(alexa, fieldnames=fields)
		for z in alexalist:
			if z['domain'] not in alexaset:
				alexaset.append(z['domain'])
	print 'done'		

	print 'Freq-Table-rating and clustering by rating...'

        for row in reader:

                row['rating'] = 0							#init rating
		request = ''

		try:									#if "request" starts with www. replace with ""
			request = row['request'].replace("www.", "")			#to get more appropiate ratings
			row['request'] = request					#could also be done in following split()
		except:
			request = row['request']  
		
		
		
		request = request.split('.')
		
		parserequest = ""							#kill tld from request string
		s = ""
		for x in range(len(request)-1):		
			parserequest += s.join(request[x])
			parserequest += '.'
		


		#this would be needed for another testing version of alexa testing 
		#for alexa_domain in alexa_domains:
			#if domain_to_test.endswith(alexa_domain):
				# kick
		
		#alexarequest = ""
		#t = ""
					
		#if (len(request)) > 2:		
		#	for y in range(len(request)-1):				
		#		
		#		alexarequest += t.join(request[y+1])
		#		if y < (len(request)-2):				
		#			alexarequest += '.'
		
		#if (len(request)) <= 2:
		#	alexarequest = row['request']
		




	
		
		


		
		request = parserequest
		prob = lib.probability(request)					#adjust rating for shortend request
               	row['rating'] = prob

		if  row['rating'] < noise  :	
										#is 0 when row['rating'] == "" or all chr are the same
				#print request					#4 debugging
				row['rating'] = row['rating'] + nxthreshold    	#put noise over threshold

		

		if len (request) > 6:




				
			#for other version of alexa testing too
			#if  row['rating'] < threshold :			


				
			


			#	alexaset = []
	
			#	with open('top-1m.csv', 'r') as alexa:
			#		fields = ['count','domain']
        		#		alexalist = csv.DictReader(alexa, fieldnames=fields)
			
			#		if alexarequest not in alexaset:
			#			for z in alexalist:
			 #  				if alexarequest == z['domain']:
			#					row['rating'] = row['rating'] + nxthreshold    	#put top1m domains over threshold
			#					alexaset.append(z['domain'])
								

			#		if alexarequest in alexaset:
			#			row['rating'] = row['rating'] + nxthreshold    	#put top1m domains over threshold
			









			if  row['rating'] < threshold :
				if row['request'] in alexaset:
					row['rating'] = row['rating'] + nxthreshold
					print row
				#print row['request']

				#if row['request'] not in alexaset:

			if  row['rating'] < threshold :	
				if row['request'] not in dgadomains:			
					dgadomains.append(row['request'])
					#print row['request']					#4 debugging

				if row['anonymized_hash'] not in infected:			
					infected.append(row['anonymized_hash'])
					#print row['anonymized_hash']				#4 debugging

			if  row['rating'] < nxthreshold and row['response'] == 'ip_0000':

				if row['request'] not in dgadomains:
						container.append(row)
						#print 'NXDomain: ',request			#4 debugging

				


        print 'done'

        multiNX = 'multiNX'
        user = 'user'
        
	multiset = []

	timesseen = float(raw_input('How many users have to query NXDomain to get it rated? 3 recommended) '))
	#timesseen = 3
	print 'Rating all NXDOMAINs in cluster...'
	

	
  	for row in container:
		
		multiNX = row['request']
		
		               
               
                uset = []
				
		if multiNX not in multiset: 

                        #multiNX = row['request']					#4 debugging
                        user = row['anonymized_hash']
                        row['rating'] = row['rating'] - 1
                        
			multiset.append(multiNX)
                        #print row							#4 debugging

			i = 0
			
                	for row in container:

				


                        	if row['request'] == multiNX:

					i = i + 1
                                
                        	        row['rating'] = row['rating'] - 1	
					if row['anonymized_hash'] not in uset:
						uset.append(row['anonymized_hash'])	#contains users for treated multi NXDomain 
						
											
					

			
			if i > timesseen - 1 :							#if NXDomain seen by multiple users
				#print multiNX,' found',i,' times.'
				
				if multiNX not in dgadomains:				#add unseen NXDomain to generated domains
          				dgadomains.append(multiNX)			#assuming typos not made by multiple users
				for item in uset:
					
					if item not in infected:			#add unseen users who queried NXDomain to infected
						infected.append(item)
						
						#print row['anonymized_hash']

				
					

	dgadomains_nr = 0
	infected_nr = 0

	print 'done with all multi-NX'
	
	print 'Saving all generated domains to ***dgadomains.txt***'


	
	for row in dgadomains:	
		#print row								#4 debugging
		dgadomains_nr = dgadomains_nr + 1
		with open('dgadomains.txt','a') as dga: 
			dga.write("%s\n" % row)
	

	print 'Adding ratings for each host...'
	print 'Saving all possible infected user names to ***infected.txt***'

	for row in infected:
		#print row								#4 debugging
		infected_nr = infected_nr + 1
		with open('infected.txt','a') as inf: 
			inf.write("%s\n" % row)

	print 'Detected', dgadomains_nr, 'different generated domains.'        
	print 'Detected', infected_nr, 'infected hosts.'        
             

 
        
                                                            

 	

                                      
