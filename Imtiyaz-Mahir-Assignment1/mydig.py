import dns.message
import dns.query
import dns.rdatatype
import dns.exception
import datetime
import sys
import time

def mydig(domain, server):
    try:
        req = dns.message.make_query(domain, 'A')      #DNS query for domain and A
        res = dns.query.udp(req, server, 5)            #send query to root server, times out after 6 seconds
    except dns.exception.Timeout:
        print("Request timed out")
        exit()
    except BlockingIOError:
        print("BlockingIOError")
        exit()
    except:
        print("Cannot resolve domain")
        exit()

    while True:
        #if there's an answer, check if its A or a CNAME, if A return answer else recursively call mydig with CNAME
        if res.answer:
            if res.answer[0].rdtype == dns.rdatatype.A: 
                return res.answer

            if res.answer[0].rdtype == dns.rdatatype.CNAME:
                return mydig(res.answer[0].to_text().split(' ')[-1], '198.41.0.4')
            
        #if there's no answer, then check additional and recursively call each IP in additional
        elif res.additional:
            for IP in res.additional:
                if ':' not in IP[0].to_text():
                    return mydig(domain, IP[0].to_text())

        #if no answer or additional, if there's an NS then make recursive call with name server
        elif res.authority:
            for elem in res.authority:
                if ' IN NS ' in elem.to_text():
                    ns = mydig(elem.to_text().split(' ')[-1], '198.41.0.4')
                    return mydig(domain, ns[0].to_text().split(' ')[-1])
                else:
                    return None

        else:
            return None

def main():

    domain = sys.argv[1]                        #grabs the domain from the command line arg
    start = time.time()                         #start time 
    IP = mydig(domain, '198.41.0.4')            #calling mydig with the provided domain
    end = time.time()                           #end time  
    if IP == None:
        print("Failed to resolve domain.")
    else:
        output = IP[0].to_text().split(' ', 1)[1]   #removing the first word from the answer

        print('QUESTION SECTION:')
        print(f'{domain}. IN A')
        print('\nANSWER SECTION:')
        print(f'{domain}. {output}\n')
        print(f'Query time: {(end - start) * 1000:.2f} ms\n')
        print(f'WHEN: {datetime.datetime.now().strftime("%a %b %d %Y %H:%M:%S")}')

if __name__ == "__main__":
    main()
