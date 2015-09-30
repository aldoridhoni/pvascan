# pvascan
Python vulnerability scanner tool which using [Exploit-DB][edb] files.csv as vulnerability database reference. 
This is just a Proof of Concept tool that automation Vulnerability Assessment while scanning port of Operating System.

#####Some factors that influence result of pvascan :
* Application/service banner of [nmap][nmp] result scan.
* Randomly named application/service at description [files.csv][csv] of Exploit-DB.

#####Screenshots of pvascan :
![alt text][sc1]
![alt text][sc2]

[edb]: https://www.exploit-db.com/
[nmp]: https://nmap.org/
[csv]: https://raw.githubusercontent.com/offensive-security/exploit-database/master/files.csv
[sc1]: https://lh3.googleusercontent.com/-9GWz23RliXQ/VgqJ8IlLIAI/AAAAAAAAB_I/M6qkhILKkQI/h409/pvascandemo.png "default scan"
[sc2]: https://lh3.googleusercontent.com/-joWUyeeOIrQ/VgqKNTisfhI/AAAAAAAAB_Q/NTmjeKln5JU/h409/pvascandemop.png "port scan"
