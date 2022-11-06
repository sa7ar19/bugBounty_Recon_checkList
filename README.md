# bugBounty_chickList
- [ ]  create folders < subdomains , urls, ips, patterns, js >

# Finding root domains

- [ ]  **ASN Enum**
- **To find it :**
    - **manually  :**
    [http://bdp.he.net](http://bdp.net) 
    rogue assets could exist on cloud environments like AWS and azure , here we can several ip ranges.
    - **For Automation but manually is better than it :**
    metabigor # or # net by j2ssiejjj # **[Asnlookup](https://github.com/yassineaboukir/Asnlookup)**
    
    ```bash
    cat "Domain" | metabigor net --org -v
    ```
    
    [Asnlookup/asnlookup.py at master · yassineaboukir/Asnlookup](https://github.com/yassineaboukir/Asnlookup/blob/master/asnlookup.py)
    
- [ ]  **CIDR ranges**
- **To find it :**
    
    Depending on the size of the organization
    
    ```bash
    #whois
    $ whois 157.240.2.35
    **NetRange: 157.240.0.0 - 157.240.255.255  <=**
    **CIDR: 157.240.0.0/16
    ####**
    #ASN to CIDR
    whois -h whois.radb.net -- '-i origin <ASN Number Here>' | grep -Eo "([0-
    9.]+){4}/[0-9 {4}/[0-9]+" | sort -u     
    #-h ⇒ retrieve information from & [whois.cymru.com](http://whois.cymru.com/) ⇒ is a database that translates IPs to ASNs
    # Whois CIDR
    $whois -h whois.radb.net -- '-i origin <ASN(20360)>
    ####
    amass i amass intel -asn <ASN Number Here>
    ```
    
- [ ]  **root domains**
- **To find it :**
    
    ```bash
    #amass with ASN
    $ amass intel -asn <46489>
    $ amass intel -org <target(oppo)> -max-dns-queries 2500
    #amass with reverse whois => to find domains that were registered using the
    #same email.
    $ amass intel -whois -d <Domain Name Here>
    #or#
    # by google dorks 
                 intitle:”copyright”
                 site [target.com](http://target.com) -site:www.target.com”
    #shodan
                1- Net:”CIDR”
                2- org:<company name>
                3- Ssl:<company name>
    2- Term of service text
    3- privacy policy text
    ```
    
    Automation tool : 
    
    ‣
    
    ### nslookup & Domain-Eye
    
    [Reverse IP, NS and MX](https://domaineye.com/)
    
    ```bash
    nslookup facebook.com -type=MX // NS // A 
    ```
    
    <aside>
    📎 We can use reverse IP, reverse name server, and reverse mail server
    searches to find [domains](http://domains.in) with ⇒  [https://domaineye.com/](https://domaineye.com/)
    
    </aside>
    
    - [ViewDNS.info](http://viewdns.info/)
    
    ## onther way
    
    ●[https://opendata.rapid7.com/sonar.fdns_v2/](https://opendata.rapid7.com/sonar.fdns_v2/) 
    ●[https://opendata.rapid7.com/sonar.fdns/](https://opendata.rapid7.com/sonar.fdns/) 
    
    ```bash
    zgrep ‘\.domain\.com”,’ path_to _dataset.json.gz
    ```
    
    This process is fairly slow as your system has to grep through 30GB of text. This technique should provide you with a very large list of subdomain
    
    - CIDR
        
        Utilizing the companies CIDR ranges we can perform a reverse IP search to find any domains that are hosted on those IPs
        
    
    ```bash
    # Amass CIDR
    $amass intel -cidr <CIDR Range Here>
    ```
    
    - Certificate Parsing
        
        the Secure Sockets Layer (SSL) certificates
        
        **Certification Transparency Logs**
        
        An SSL certificate’s Subject Alternative Name field lets certificate owners specify additional hostnames
        that use the same certificate, so you can find those hostnames by parsing this field. Use online databases like [crt.sh](http://crt.sh/), Censys, and Cert Spotter to find certificates for a domain.
        
    - [ ]  [**crt.sh](http://crt.sh/)** 
    USAG : [https://crt.sh/](https://crt.sh/)?[q=facebook.com](http://q%3Dfacebook.com/)&output=json.
    ●[https://github.com/ghostlulzhacks/CertificateTransparencyLogs](https://github.com/ghostlulzhacks/CertificateTransparencyLogs)
    
    ```bash
    python certsh.py -d < Domain >
    ```
    
    another tool use ssl 
    
    - [ ]  **Sublert** ⇒ for domains monitoring

## Acquisitions

- **investigate from :**
    
    **make sure** that it still owned by the company .
    
    1. [https://crunchbase.com](https://crunchbase.com) 
    2. wikipedia
    3. Google

---

## SubDomains

- [ ]  **recon_ng**
- **Usage :**
    
    ```bash
    > workspaces  # creat 
    - workspaces creat ifood.com
    > db insert domains 
    > db insert copanies
    > module search domains-hosts
    > modules load <module-name> # brute-hosts
    > info
    #to change wordlist
    > options set WORDLIST <word-list>
    > run
    ###################
    > modules load recon/domains-hosts/builtwith    #domains-hosts -> for rec subdomains
    > info
    keys: builtwith_api
    > run
    ################
    >cirtificate_transparency + hackertarget + mx_spf_ip + netcraft + shodan** + ssl_sa* + threat  
    >run
    ################
    > show hosts
    > dashboard
    
    ###########
     > modules search resolve      #to Get The ips
    > use recon/hosts-hosts/resolve
    > use recon/hosts-hosts/reverse_resolve
    #########
    > modules search reporting    # 
    > modules load ****/list
    > ls
    > options set  <columns ip_dress>
    >  options set FILENAME /ips/ips.txt
    ```
    
- [ ]  **Amass**
- **Usage :**
    
    **⇒**  uses a combination of DNS zone
    transfers, certificate parsing, search engines, and subdomain databases to find subdomains
    
    ```bash
    amass enum -passive -d [subdomain] -v
    ```
    
- [ ]  **Subfinder**
- **Usage :**
    
    ```bash
    $ subfinder -d <domain> -recursive -silent
    ```
    
- [ ]  **github-subdomains.py**
- **Usage :**
    
    with github api 
    → rate limit | sleep
    run 5 of them with 5 seconed between them
    
- [ ]  **Shosubgo → inc0gbyt3**
- **Usage :**
    
    gathering subdomains from shodan
    
- [ ]  **AssetFinder**
- [ ]  **SubBrute**
- [ ]  **Gobuster**
- **Usage :**
    
    ```bash
    gobuster dns -d target_domain -w wordlist
    #Its DNS mode is used for subdomain bruteforcing
    ```
    
- [ ]  **Sublist3r ⇒** works by querying search engines and online subdomain databases
- [ ]  findomain
- [ ]  [Knock.py](http://knock.py/)
- **Usage :**
    
    ```bash
    knockpy.py <Domain Name Here>
    ```
    

⇒ Also look for subdomains of subdomains

## subdomains brute-force

- [ ]  **amaas**
- **Usage :**
    
    ```c
    amass enum -brute -d domain.com -src
    #it has a built in list but you can specify your own
    #you can specify the number of DNS resolvers
    amass enum -brute -rf resolvers.txt -w bruteforce.list
    ```
    
- [ ]  **shuffleDNS**
- **Usage :**
    
    ```c
    shuffledns -d domain.com -w wordlist.txt -r resolvers.txt
    ```
    
    **Wordlists ⇒** all.txt
    
- [ ]  **alteration scanning ⇒ altdns**
- **Usage :**
    
    ```bash
    $ altdns -i domains.txt -o altdns_output -w wordlist.txt -r -s resolved_output.txt  #take alot of time #6 hour*
    ```
    

## validation

- [ ]  **Httpx   #for subdomains**
- **Usage :**
    
    ```bash
    cat subdomains.txt | httpx -verbose > urls/urls.txt
    ```
    
- Massdns
    
    If you have a If you have a list of subdomains you can use Massdns to
    determine which ones are live domains.
    ●  [https://github.com/blechschmidt/massdns](https://github.com/blechschmidt/massdns) 
    The tool is written in C and requires us to build it before we can use it. To do so run the following command:
    git install [https://github.com/blechschmidt/massdns.git](https://github.com/blechschmidt/massdns.git)
    cd massdns
    
     make
    
    Note that in order to parse out the live domains we will need to parse the tools
    output. This can be done with a json parse, I will be using JQ for this. JQ is a
    command line json parser.
    ●  [https://github.com/stedolan/jq](https://github.com/stedolan/jq) [https://github.com/stedolan/jq](https://github.com/stedolan/jq)
    Another thing to n hing to note is that  you must also have a list  of DNS resolvers for the tool to use. The most popular one is Googles “8.8.8.8”. If you have a large list you may want to add more.
    The tool can be run with the following command:
    
    ```bash
    ./bin/massdns -r resolvers.txt -t A -o J subdomains.txt | jq 'select(.resp_type=="A" ) | .query_name' | sort -u
    ```
    
    Resolvers.txt should hold your list of DNS resolvers and subdomains.txt holds the domains you want to check. This is then piped to JQ where we parse out all domains that resolve to an IP. Next, we use the sort command to remove any duplicates.
    
- **Usage :**
- [ ]  [isup.sh](http://isup.sh) #for ips
- **Usage :**
    
    ```bash
    ./isup.sh ips.txt 
    # it will save the result in /tmp 
    # Don't forget to remove them after saving
    ```
    

## Discovery

- [ ]  **masscan**
- **Usage :**
    
    ```c
    masscan -p1-65535 -iL $ipFile --max-rate 1800 -oG $outputFile.log
    ```
    
- [ ]  **dnmasscan**
- **Usage :**
    
    ```c
    dnmasscan example.txt dns.log -p80,443 -oG masscan.log
    ```
    
- [ ]  **nmap**
- **Usage :**
    
    ```bash
    nmap -iL valid_ips.txt -sSV -A -T4 -O -Pn -v -F -oN file.tx
    ```
    
- [ ]  **brutespray**
- **Usage :**
    
    When we get this services/ports info we can feed it to nmap to get a OG output
    
    We  can then scan the remote administration protocols for default passwords with a tool like brutespray which take the OG file format
    
- [ ]  **Sniper**
- **Usage :**
    
    massive scan ((take alot of time))
    
    ```bash
    sniper -f valid_ips.txt -m massweb -w  <work-space name>
    ```
    
- [ ]  **Github**
- **Usage :**
    
    [https://gist.github.com/jhaddix/77253cea49bf4bd4bfd5d384a37ce7a4](https://gist.github.com/jhaddix/77253cea49bf4bd4bfd5d384a37ce7a4) 
    [https://www.youtube.com/watch?v=l0YsEk_59fQ](https://www.youtube.com/watch?v=l0YsEk_59fQ) 
    
    [GitHub ](https://www.notion.so/GitHub-41596c448d444b2380b7b352d6214e3c) 
    
- [ ]  **check for heartbleed :**
- **Usage :**
    
    ```bash
    cat [urls/ips].txt | while read line ; do echo "QUIT" | openssl s_client -connect $line:443 2>&1 | grep 'server extention "heartbleed" (id=15) || echo $line: safe; done   #if safe => npt vulnerable
    ```
    

## Jave Script Files

- [ ]  **getJS**    #to get js
- **Usage :**
    
    ```bash
    getJS --url website.com --output results.txt # from the website directly
    getJS -input urls.txt --output results.txt # from the website directly
    #or using proxychin
    service tor starts
    proxychains getjs --url website.com --output /js/results.txt
    ```
    
- [ ]  Extract urls from js files
- **Usage :**
    
    ```bash
    # From any type if file :
    cat file | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*"*
    #Directly From a website :
    curl https://web.com/file.js |grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*"*
    ```
    
- [ ]  scan for secrets
- **Usage :**
    
    ```bash
    gitleaks --path=/directory -v --no-git
    # Scan a file with Any Extention for secrets!
    gitleaks --path=/file.xxx -v --no-git
    ```
    
- [ ]  Check Keys/Tokens when you found it
- **Usage :**
    
    ```bash
    # keyhacks tool
    ```
    
- [ ]  parameters
- **Usage :**
    
     { checking with sqlmap or gsql }
    paramspider  ⇒ [https://github.com/devanshbatham/ParamSpider](https://github.com/devanshbatham/ParamSpider)
    
    ```bash
    python3 paramspider.py --domain DOMAINNAME.com --exclude woff,png,svg,php,jpg --output /root/param.txt
    ```
    
- [ ]  pattern check with gf & gf-patterns :
- **Usage :**
    
    ```bash
    cat js.txt | gf  #take a look at what id can do 
    #after you have parameters Gathred, we want to check for specific patterns and possible vuln urls that can be attacked using Meg or other tools
    cat params.txt | gf xss | sed 's/FUZZ/ /d' >> xss_params_forMeg.txt
    ```
    
- [ ]  Check for domain Take over
- **Usage :**
    
    subOver  & nucleiI & takeover 
    
    ```bash
    takeover -l sub_doma.txt -v -t 10
    ```
    
- [ ]  check for open Amazon S3 buckets,  digitaloceanspace , azureblobstorage
- **Usage :**
    
    ```bash
    ls | grep s3 from nuclei-emplates/technologies
    -------
    nuclei -l urls.txt -t /roo/nuclei-templates/technologies/s3-detect.yaml
    -------
    spiderfoot -m sfp_azureblobstorage,sfp_s3bucket.sfp_digitaloceanspace -s < DOMAIN.com> -q
    ```
    
    ‣ 
    
    - cloud_enum
    ‣
    
    ```bash
    python3 cloud_enum -k domain -k realme  
    ```
    
- [ ]  Attack bucketes
- **Usage :**
    
    [https://github.com/blackhatethicalhacking/s3-buckets-aio-pwn](https://github.com/blackhatethicalhacking/s3-buckets-aio-pwn)
    
    ```bash
    #s3-buckets-aio-pwn tool
    ```
    
- [ ]  **hunt for urls with params**   #from wayback machine with **paramspider** ///// or use **Arjun**
- **Usage :**
    
    ```bash
    python3 paramspider.py --domain domname.com --exclude woff, png, svg, php, jpg --output params.txt
    ```
    
- [ ]  check for specific patterns and possible vuln urls that can be attacked using Meg or other tools
- **Usage :**
    
    
    Jsscanner ⇒ js files for end points , secrets, hardcoded credntials, IDORS , opendirect and more 
    
    — > paste urls into alive.txt 
    
    — > run script alive.txt  - examine the results using GF advanced patterns 
    — > use tree command , cat into subdirectories : cat * */**.txt 
    
    cat /*/*.txt |gf api-keys ⇒ what you wonna look for  # Tab
    
    cat /*/*.txt | gf ssrf > /root/Desktop/ssrf.txt
    
    ```bash
    cat params.txt | gf xss | sed 's/FUZZ/ /d' >> xss_params_forMeg.txt
    meg -v LFI-gracefulsecurity-linux.txt urls.txt /urls.txt -s 200
    ```
    
    /usr/share/seclists/Fuzzing
    
- [ ]  **check for xss**
- **Usage :**
    
    
    1. first replace FUZZ with xss to tell dalfox where to inject :
    
    ```bash
    sed 's/FUZZ/ /g' param.txt > xss-param.txt
    cat xss-param.txt | dalfox pipe | cut -d " " -f 2 > output.txt
    #or 
    dalfox file xss-param.txt |cut -d " " -f 2 > output.txt
    # for deeper attacks add : --deep-domxss
    #silence --silence Prints only PoC when found and progress
    ```
    
- [ ]  **Nuclei**
- **Usage :**
    
    ```bash
    #1- Nuclei 
    amass enum -passive -d [subdomain] -v | httpx -verbose | nuclei -t /root/nuclei-templates/cves/ -o /location.txt
    ```
    
- [ ]  **Jaeles**
- **Usage :**
    
    ```bash
    amass enum -passive -d [subdomain] -v | httpx -verbose | jaeles scan -s 'cves' -s 'sensitive' -s 'fuzz' -s 'common' -s 'routines' report -o reportname.txt --title "[Client] Jaeles Fill Report"
    ```
    
- [ ]  **osmedeus server**  #VPS recommended
- **Usage :**
    
    ```bash
    # Directly run on vuln scan and directory scan on list of domains 
    osmedeus scn -f vuln-nd-dirb -t list-of-domains.txt
    ```
    
- [ ]  chopchop
- **Usage :**
    
    ```bash
    ./gochopchop scan --url-file urls.txt --threads 4
    ```
    
- [ ]  Sniper
- **Usage :**
    
    ```bash
    sniper -f valid-ips.xt -m massweb -w webname
    ```
    
- [ ]  take screen shots
- **Usage :**
    
    ```bash
    #Eyewitness :
    $eyewitness -f urls.txt  --web --timeout 8
    cat urls | qscreenshot
    #Aquatone 
    visual recon
    cat alivedomains.txt | aquaton -ports 80,443,8080
    #httpscreenshot
    ```
    
- [ ]  **updog**
- **Usage:**
    
    ```bash
    curl ipecho.net ; echo
    updog -d /root/ -p 1337
    ```
    
    ‣
    
    result of screenshots EyeWitness > updog
    

