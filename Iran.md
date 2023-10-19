# **Iran - Israel Cyber Attacks**

- ### [2020 April. 24-25](https://www.timesofisrael.com/6-facilities-said-hit-in-irans-cyberattack-on-israels-water-system-in-april/)
  > Iran suspected of attacking 6 water facilities in Israel


- ### [2020 May. 9](https://www.timesofisrael.com/israel-said-behind-cyberattack-that-caused-total-disarray-at-iran-port-report/)
  > Israel suspected of attacking Iran's Shahid Rajaee port in retaliation for the April attacks on water facilities in Israel
	

- ### [2021 Aug](https://www.welivesecurity.com/en/eset-research/sponsor-batch-filed-whiskers-ballistic-bobcats-scan-strike-backdoor/) : Ballistic Bobcat (APT35)
  > Israeli insurance companies attacked by the Sponsor Backdoor (get link)
 
    - **IOCs**
      - <ins>Samples</ins>
		```
		Sponsor backdoor
		Plink Backdoor
		Merlin Agent	
		```
      - <ins>Filenames</ins>
		```
		MicrosoftOutlookUpdateSchedule
		MicrosoftOutlookUpdateSchedule.xml
		GoogleChangeManagement
		GoogleChangeManagement.xml
		windowsprocesses.exe
		install.bat
		```
      - <ins>Domains</ins>
		```
		162.55.137[.]20
		http://162.55.137[.]20/gsdhdDdfgA5sS/ff/dll.dll
		http://162.55.137[.]20/gsdhdDdfgA5sS/ff/windowsprocesses.exe
		37.120.222[.]168:80
		```

- ### [2021 Sep -> Jun](https://www.ynetnews.com/business/article/rjrs5pn02) : Ballistic Bobcat (APT35)
  > Iranian hackers break into more than 30 companies in Israel
	

- ### [2021 Sep](https://research.checkpoint.com/2021/mosesstaff-targeting-israeli-companies/)
  - <ins>MosesStaff</ins>
	Iranian-linked group carried out targeted attacks against Israeli companies, leaked their data, and encrypted their networks. 
	
		IOCs
			DiskCrypter is a legitimate open-source encryption utility
			IISpool.apsx Webshell: 52a04efc6a0e7facf34dcc36a6d1ce6f 
			PyDCrypt 
			DCSrv 
			StrifeWater RAT
			Telegram Channel:
				https://t.me/moses_staff

- ### [2021 Oct 26](https://www.reuters.com/world/middle-east/iran-says-cyberattack-behind-widespread-disruption-gas-stations-2021-10-26/)
  - Iran blamed Israel and the US for attacking it's gas stations nationwide
	

- ### [2022 Feb](https://research.checkpoint.com/2022/check-point-research-exposes-an-iranian-phishing-campaign-targeting-former-israeli-foreign-minister-former-us-ambassador-idf-general-and-defense-industry-executives/)
  - Iranian Spear-Phishing attack against high-ranking Israeli officials
		IOCs
			de-ma[.]online
			litby[.]us

- ### [2023 Feb](https://blogs.blackberry.com/en/2023/02/darkbit-ransomware-targets-israel)
	- The Iranian group **MuddyWater** used **Darkbit** Ransomware to attack the Israeli Technion University
    	- IOCs
			```
			Darkbit Ransomware:
				9107be160f7b639d68fe3670de58ed254d81de6aec9a41ad58d91aa814a247ff 
			```

## General Summary
	Iran has two known top-level agencies that are responsible for most of the cyber operations.
	IRGC (Islamic Revolutionary Guard Corps) reports directly to the Iranian supreme leader (Ali Khamenei), 
	and MOIS (Ministry of Intelligence and Security (VEVAK in Farsi) reports to the president.

	The IRGC also contracts private companies like Emennet Pasargad (Cotton Sandstorm), 
	Afkar Systems and Najee Technologies (Nemesis Kitten/APT35 Cluster)
	Some of the prominent targets are Israel, the United States, the United Arab Emirates, 
	Bahrain, Saudi Arabia, and Iranian political adversaries...

	Iranian cyber operations vary from regular cyber attacks 
	(e.g. ransomware, wipers, defacement, sabotage, denial of service, surveillance and credential theft), 
	to manipulation and influence campaigns aka Cyber Enabled Influence Operations (IOs). 
	Themes like Palestinian resistance, Shi'ite unrest in the Gulf, counter Arab-Israeli normalization and economic relations, 
	cause panic/fear among Israelis, political manipulations in the US, 
	and exposing corrupt or embarrassing activities of Iranian adversaries.


## Known Iranian APT Groups and their known IOCs

### IRGC (Islamic Revolutionary Guard Corps)
- Cotton Sandstorm (Influence Operations)
- Fox Kitten
- APT 33
- APT 35 (Cluster)
- Charming Kitten (aka Phosphorus)
- Mint Sandstorm
- ITG18
- TA453 
- Cobalt Mirage
- APT 42
- Nemesis Kitten
- PHOSPHORUS
- Ballistic Bobcat
- Imperial Kitten (aka TortoiseShell)

### MOIS (Ministry of Intelligence and Security) 
*Aka VEVAK (in Farsi) previously SAVAK*
- MuddyWater (aka Static Kitten/Mango Sandstorm)
	- IOCs
		```
		SyncroRAT
		DarkBit Ransomware
			9107be160f7b639d68fe3670de58ed254d81de6aec9a41ad58d91aa814a247ff
		```
- DarkBit (aka DEV-1084)
- OilRig (aka APT 34)
- Hexane (aka Lyceum)
- Agrius
- Domestic Kitten (APT-C-50)
	IOCs:
		FurBall (Android, Domestic Kitten)
			https://www.eset.com/int/about/newsroom/press-releases/research/masquerading-as-a-translation-app-furball-spyware-goes-after-iranian-citizens-eset-research-finds/


## Known Tools and Malware
- [FurBall](https://www.eset.com/int/about/newsroom/press-releases/research/masquerading-as-a-translation-app-furball-spyware-goes-after-iranian-citizens-eset-research-finds/) (Android, Domestic Kitten)
- [TelegramGrabber](https://www.pwc.com/gx/en/issues/cybersecurity/cyber-threat-intelligence/old-cat-new-tricks.html) (Win32 EXE, Yellow Garuda)
- [PineFlower] (Android)



### Sources:
- https://blogs.microsoft.com/on-the-issues/2023/05/02/dtac-iran-cyber-influence-operations-digital-threat/
- https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RW13xRJ
- https://blog.sekoia.io/iran-cyber-threat-overview/
- https://iranprimer.usip.org/blog/2023/may/03/report-iran-accelerates-cyberattacks
- https://www.darkreading.com/ics-ot/israeli-irrigation-water-controllers-postal-service-breached
- https://www.ynet.co.il/digital/technews/article/s1js11exg2
- https://research.checkpoint.com/2021/mosesstaff-targeting-israeli-companies/
- https://www.welivesecurity.com/2022/10/20/domestic-kitten-campaign-spying-iranian-citizens-furball-malware/
- https://www.timesofisrael.com/iran-cyberattack-on-israels-water-supply-could-have-sickened-hundreds-report/
- https://www.gov.il/en/departments/news/_muddywater
- https://www.welivesecurity.com/en/eset-research/sponsor-batch-filed-whiskers-ballistic-bobcats-scan-strike-backdoor/
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-321a