# CVE_Assessment_08_2019

This is a review of TeamViewer.The software has a possible integrity vulnerability. While examining the software it was identified a similar JA3 hash signature (“4d7a28d6f2263ed61de88ca66eb011e3”) associated with malware samples that could be using encryption to hide themselves in the noise. 

A possible explanation for this finding may be due to the inappropriate use of JA3 during the development or recent updates of the software.


References

https://www.virustotal.com/gui/file/039f2bd2f17e11324e832e83eb41147e2c120475d52be78927198a6dcbbc55c1/behavior/VirusTotal%20Jujubox

https://www.hybrid-analysis.com/sample/039f2bd2f17e11324e832e83eb41147e2c120475d52be78927198a6dcbbc55c1

https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/inspecting-encrypted-network-traffic-with-ja3/

https://www.malwarebytes.com/emotet/ 

https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967

https://sslbl.abuse.ch/ja3-fingerprints/4d7a28d6f2263ed61de88ca66eb011e3/

https://github.com/salesforce/ja3 
