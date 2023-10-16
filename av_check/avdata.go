package av_check

var (
	version string = "1.1.0"
	// 输出结果文件
	outfile string
	// 识别本机进程
	localpro bool
	// 识别指定进程
	proce string
	// 识别指定进程文件
	procefile string
	// 存放进程名字
	processeslist []string
	// 要添加自定义的杀软进程
	avfile string
)

// 存放杀软特征库
var Avdatalist = []AvType{
	{
		Name:      "ALYac",
		Processes: []string{"aylaunch.exe", "ayupdate2.exe", "AYRTSrv.exe", "AYAgent.exe"},
		Url:       "https://en.estsecurity.com/",
	}, {
		Name:      "AVG",
		Processes: []string{"AVGSvc.exe", "AVGUI.exe", "avgwdsvc.exe", "avg.exe", "avgaurd.exe", "avgemc.exe", "aAvgApi.exe", "avgrsx.exe", "avgserv.exe", "avgw.exe"},
		Url:       "https://www.avg.com/",
	}, {
		Name:      "Acronis",
		Processes: []string{"arsm.exe", "acronis_license_service.exe"},
		Url:       "https://www.acronis.com/",
	}, {
		Name:      "Ad-Aware",
		Processes: []string{"AdAwareService.exe", "Ad-Aware.exe", "AdAware.exe"},
		Url:       "https://www.adaware.com/",
	}, {
		Name:      "AhnLab-V3",
		Processes: []string{"patray.exe", "V3Svc.exe"},
		Url:       "https://global.ahnlab.com/site/main.do",
	}, {
		Name:      "Arcabit",
		Processes: []string{"arcavir.exe", "arcadc.exe", "ArcaVirMaster.exe", "ArcaMainSV.exe", "ArcaTasksService.exe"},
		Url:       "https://www.arcabit.pl",
	}, {
		Name:      "Avast",
		Processes: []string{"ashDisp.exe", "AvastUI.exe", "AvastSvc.exe", "AvastBrowser.exe", "AfwServ.exe"},
		Url:       "https://www.avast.com",
	}, {
		Name:      "Avira AntiVirus",
		Processes: []string{"avcenter.exe", "avguard.exe", "avgnt.exe", "sched.exe"},
		Url:       "https://www.avira.com/",
	}, {
		Name:      "Baidu AntiVirus",
		Processes: []string{"BaiduSdSvc.exe", "BaiduSdTray.exe", "BaiduSd.exe", "bddownloader.exe", "baiduansvx.exe"},
		Url:       "https://anquan.baidu.com/",
	}, {
		Name:      "BitDefender",
		Processes: []string{"Bdagent.exe", "BitDefenderCom.exe", "vsserv.exe", "bdredline.exe", "bdservicehost.exe"},
		Url:       "http://www.bitdefender.com/",
	}, {
		Name:      "Bkav",
		Processes: []string{"BKavService.exe", "Bka.exe", "BkavUtil.exe", "BLuPro.exe"},
		Url:       "https://www.bkav.com/",
	}, {
		Name:      "CAT-QuickHeal",
		Processes: []string{"QUHLPSVC.exe", "onlinent.exe", "sapissvc.exe", "scanwscs.exe"},
		Url:       "https://www.quickheal.com/",
	}, {
		Name:      "CMC",
		Processes: []string{"CMCTrayIcon.exe"},
		Url:       "https://cmccybersecurity.com/",
	}, {
		Name:      "ClamAV",
		Processes: []string{"freshclam.exe"},
		Url:       "https://www.clamav.net",
	}, {
		Name:      "Comodo",
		Processes: []string{"cpf.exe", "cavwp.exe", "ccavsrv.exe", "cmdvirth.exe"},
		Url:       "https://www.comodo.com",
	}, {
		Name:      "CrowdStrike Falcon",
		Processes: []string{"csfalconservice.exe", "CSFalconContainer.exe"},
		Url:       "https://www.crowdstrike.com",
	}, {
		Name:      "Cybereason",
		Processes: []string{"CybereasonRansomFree.exe", "CybereasonRansomFreeServiceHost.exe", "CybereasonAV.exe"},
		Url:       "https://www.cybereason.com/",
	}, {
		Name:      "Cylance",
		Processes: []string{"CylanceSvc.exe"},
		Url:       "https://www.cylance.com",
	}, {
		Name:      "Cyren",
		Processes: []string{"vsedsps.exe", "vseamps.exe", "vseqrts.exe"},
		Url:       "http://www.cyren.com/",
	}, {
		Name:      "DrWeb",
		Processes: []string{"drwebcom.exe", "spidernt.exe", "drwebscd.exe", "drweb32w.exe", "dwengine.exes"},
		Url:       "https://www.drweb.com/",
	}, {
		Name:      "ESET-NOD32",
		Processes: []string{"egui.exe", "ecls.exe", "ekrn.exe", "eguiProxy.exe", "EShaSrv.exe"},
		Url:       "https://www.eset.com/us/home/antivirus/",
	}, {
		Name:      "Emsisoft",
		Processes: []string{"a2cmd.exe", "a2guard.exe"},
		Url:       "https://www.emsisoft.com/",
	}, {
		Name:      "Endgame",
		Processes: []string{"endgame.exe"},
		Url:       "https://www.endgame.com/",
	}, {
		Name:      "F-Prot",
		Processes: []string{"F-PROT.exe", "FProtTray.exe", "FPAVServer.exe", "f-stopw.exe", "f-prot95.exe", "f-agnt95.exe"},
		Url:       "http://f-prot.com/",
	}, {
		Name:      "F-Secure",
		Processes: []string{"f-secure.exe", "fssm32.exe", "Fsorsp64.exe", "fsavgui.exe", "fameh32.exe", "fch32.exe", "fih32.exe", "fnrb32.exe", "fsav32.exe", "fsma32.exe", "fsmb32.exe"},
		Url:       "https://www.f-secure.com",
	}, {
		Name:      "FireEye",
		Processes: []string{"xagtnotif.exe", "xagt.exe"},
		Url:       "https://www.fireeye.com/",
	}, {
		Name:      "Fortinet",
		Processes: []string{"FortiClient.exe", "FortiTray.exe", "FortiScand.exe"},
		Url:       "https://fortiguard.com/",
	}, {
		Name:      "GData",
		Processes: []string{"AVK.exe", "avkcl.exe", "avkpop.exe", "avkservice.exe", "GDScan.exe", "AVKWCtl.exe", "AVKProxy.exe", "AVKBackupService.exe"},
		Url:       "https://www.gdatasoftware.com/",
	}, {
		Name:      "Ikarus",
		Processes: []string{"guardxservice.exe", "guardxkickoff.exe"},
		Url:       "https://www.ikarussecurity.com/",
	}, {
		Name:      "江民杀毒",
		Processes: []string{"KVFW.exe", "KVsrvXP.exe", "KVMonXP.exe", "KVwsc.exe"},
		Url:       "https://www.jiangmin.com/",
	}, {
		Name:      "K7AntiVirus",
		Processes: []string{"K7TSecurity.exe", "K7TSMain.Exe", "K7TSUpdT.exe"},
		Url:       "http://viruslab.k7computing.com/",
	}, {
		Name:      "Kaspersky",
		Processes: []string{"avp.exe", "avpcc.exe", "avpm.exe", "kavpf.exe", "kavfs.exe", "klnagent.exe", "kavtray.exe", "kavfswp.exe"},
		Url:       "https://www.kaspersky.com",
	}, {
		Name:      "Kingsoft",
		Processes: []string{"kxetray.exe", "ksafe.exe", "KSWebShield.exe", "kpfwtray.exe", "KWatch.exe", "KSafeSvc.exe", "KSafeTray.exe"},
		Url:       "http://www.duba.net/",
	}, {
		Name:      "Max Secure Software",
		Processes: []string{"SDSystemTray.exe", "MaxRCSystemTray.exe", "RCSystemTray.exe"},
		Url:       "https://www.maxpcsecure.com/",
	}, {
		Name:      "Malwarebytes",
		Processes: []string{"MalwarebytesPortable.exe", "Mbae.exe", "MBAMIService.exe", "mbamdor.exe", "MBAMService.exe", "mbam.exe", "mbamtray.exe"},
		Url:       "https://www.malwarebytes.com/",
	}, {
		Name:      "McAfee",
		Processes: []string{"frminst.exe", "cmdagent.exe", "cleanup.exe", "naprdmgr.exe", "udaterui.exe", "mctray.exe", "mcscript_inuse.exe", "updaterui.exe", "mcscript.exe", "scan32.exe", "mfeann.exe", "Mcshield.exe", "Tbmon.exe", "Frameworkservice.exe", "firesvc.exe", "firetray.exe", "hipsvc.exe", "mfevtps.exe", "mcafeefire.exe", "shstat.exe", "vstskmgr.exe", "engineserver.exe", "alogserv.exe", "avconsol.exe", "cmgrdian.exe", "cpd.exe", "mcmnhdlr.exe", "mcvsshld.exe", "mcvsrte.exe", "mghtml.exe", "mpfservice.exe", "mpfagent.exe", "mpftray.exe", "vshwin32.exe", "vsstat.exe", "guarddog.exe"},
		Url:       "https://www.mcafee.com/en-us",
	}, {
		Name:      "Microsoft security essentials",
		Processes: []string{"MsMpEng.exe", "mssecess.exe", "emet_service.exe", "drwatson.exe", "MpCmdRun.exe", "NisSrv.exe", "MsSense.exe", "MSASCui.exe", "MSASCuiL.exe", "SecurityHealthService.exe"},
		Url:       "https://support.microsoft.com/en-us/help/17150/windows-7-what-is-microsoft-security-essentials",
	}, {
		Name:      "NANO-Antivirus",
		Processes: []string{"nanoav.exe", "nanoav64.exe", "nanoreport.exe", "nanoreportc.exe", "nanoreportc64.exe", "nanorst.exe", "nanosvc.exe"},
		Url:       "https://nano-av.com/",
	}, {
		Name:      "a-squared free",
		Processes: []string{"a2guard.exe", "a2free.exe", "a2service.exe"},
		Url:       "https://baike.baidu.com/item/a-squared%20Free/481873?fr=aladdin",
	}, {
		Name:      "Palo Alto Networks",
		Processes: []string{"PanInstaller.exe"},
		Url:       "https://www.paloaltonetworks.com/",
	}, {
		Name:      "Panda Security",
		Processes: []string{"remupd.exe", "apvxdwin.exe", "pavproxy.exe", "pavsched.exe"},
		Url:       "https://www.pandasecurity.com/",
	}, {
		Name:      "360杀毒",
		Processes: []string{"360rp.exe", "ZhuDongFangYu.exe", "QHActiveDefense.exe", "360skylarsvc.exe", "LiveUpdate360.exe", "scrscan.exe", "safeboxTray.exe"},
		Url:       "https://sd.360.cn/",
	},
	{
		Name:      "瑞星杀毒",
		Processes: []string{"rfwmain.exe", "RsMgrSvc.exe"},
		Url:       "http://antivirus.rising.com.cn/",
	}, {
		Name:      "SUPERAntiSpyware",
		Processes: []string{"superantispyware.exe", "sascore.exe", "SAdBlock.exe", "sabsvc.exe"},
		Url:       "http://www.superadblocker.com/",
	}, {
		Name:      "SecureAge APEX",
		Processes: []string{"UniversalAVService.exe", "EverythingServer.exe", "clamd.exe"},
		Url:       "https://www.secureage.com/",
	}, {
		Name:      "Sophos AV",
		Processes: []string{"SavProgress.exe", "SophosUI.exe", "SophosFS.exe", "SophosHealth.exe", "SophosSafestore64.exe", "SophosCleanM.exe", "icmon.exe", "SavMain.exe"},
		Url:       "https://www.sophos.com/",
	}, {
		Name:      "Symantec",
		Processes: []string{"ccSetMgr.exe", "ccapp.exe", "vptray.exe", "ccpxysvc.exe", "cfgwiz.exe", "smc.exe", "symproxysvc.exe", "vpc32.exe", "lsetup.exe", "luall.exe", "lucomserver.exe", "sbserv.exe", "ccEvtMgr.exe", "snac.exe"},
		Url:       "http://www.symantec.com/",
	}, {
		Name:      "腾讯电脑管家",
		Processes: []string{"QQPCRTP.exe", "QQPCTray.exe", "QQPCMgr.exe", "QQPCNetFlow.exe", "QQPCRealTimeSpeedup.exe"},
		Url:       "https://guanjia.qq.com",
	}, {
		Name:      "TotalDefense",
		Processes: []string{"AMRT.exe", "SWatcherSrv.exe", "Prd.ManagementConsole.exe"},
		Url:       "https://www.totaldefense.com",
	}, {
		Name:      "Trapmine",
		Processes: []string{"TrapmineEnterpriseService.exe", "TrapmineEnterpriseConfig.exe", "TrapmineDeployer.exe", "TrapmineUpgradeService.exe"},
		Url:       "https://trapmine.com/",
	}, {
		Name:      "TrendMicro",
		Processes: []string{"TMBMSRV.exe", "ntrtscan.exe", "Pop3Trap.exe", "WebTrap.exe", "PccNTMon.exe"},
		Url:       "http://careers.trendmicro.com.cn/",
	}, {
		Name:      "VIPRE",
		Processes: []string{"SBAMSvc.exe", "VipreEdgeProtection.exe", "SBAMTray.exe"},
		Url:       "https://www.vipre.com",
	}, {
		Name:      "ViRobot",
		Processes: []string{"vrmonnt.exe", "vrmonsvc.exe", "Vrproxyd.exe"},
		Url:       "http://www.hauri.net/",
	}, {
		Name:      "Webroot",
		Processes: []string{"npwebroot.exe", "WRSA.exe", "spysweeperui.exe"},
		Url:       "https://www.webroot.com/us/en",
	}, {
		Name:      "Yandex",
		Processes: []string{"Yandex.exe", "YandexDisk.exe", "yandesk.exe"},
		Url:       "https://yandex.com/support/common/security/antiviruses-free.html",
	}, {
		Name:      "Zillya",
		Processes: []string{"zillya.exe", "ZAVAux.exe", "ZAVCore.exe"},
		Url:       "https://zillya.com",
	}, {
		Name:      "ZoneAlarm",
		Processes: []string{"vsmon.exe", "zapro.exe", "zonealarm.exe"},
		Url:       "https://www.zonealarm.com/",
	}, {
		Name:      "Zoner",
		Processes: []string{"ZPSTray.exe"},
		Url:       "https://zonerantivirus.com/",
	}, {
		Name:      "eGambit",
		Processes: []string{"dasc.exe", "dastray.exe", "memscan64.exe", "dastray.exe"},
		Url:       "https://egambit.app/en/",
	}, {
		Name:      "eScan",
		Processes: []string{"consctl.exe", "mwaser.exe", "avpmapp.exe"},
		Url:       "https://www.escanav.com/",
	}, {
		Name:      "Lavasoft",
		Processes: []string{"AAWTray.exe", "LavasoftTcpService.exe", "AdAwareTray.exe", "WebCompanion.exe", "WebCompanionInstaller.exe", "adawarebp.exe"},
		Url:       "https://www.lavasoft.com/",
	}, {
		Name:      "The Cleaner杀毒",
		Processes: []string{"cleaner8.exe"},
		Url:       "",
	}, {
		Name:      "VBA32杀毒",
		Processes: []string{"vba32lder.exe"},
		Url:       "http://www.anti-virus.by/en/index.shtml",
	}, {
		Name:      "Mongoosa杀毒",
		Processes: []string{"MongoosaGUI.exe", "mongoose.exe"},
		Url:       "https://www.securitymongoose.com/",
	}, {
		Name:      "Coranti2012杀毒",
		Processes: []string{"CorantiControlCenter32.exe"},
		Url:       "https://www.coranti.com",
	}, {
		Name:      "UnThreat",
		Processes: []string{"UnThreat.exe", "utsvc.exe"},
		Url:       "https://softplanet.com/UnThreat-AntiVirus",
	}, {
		Name:      "Shield Antivirus",
		Processes: []string{"CKSoftShiedAntivirus4.exe", "shieldtray.exe"},
		Url:       "https://shieldapps.com/supportmain/shield-antivirus-support/",
	}, {
		Name:      "VIRUSfighter",
		Processes: []string{"AVWatchService.exe", "vfproTray.exe"},
		Url:       "https://www.spamfighter.com/VIRUSfighter/",
	}, {
		Name:      "Immunet",
		Processes: []string{"iptray.exe"},
		Url:       "https://www.immunet.com/index",
	}, {
		Name:      "PSafe",
		Processes: []string{"PSafeSysTray.exe", "PSafeCategoryFinder.exe", "psafesvc.exe"},
		Url:       "https://www.psafe.com/",
	}, {
		Name:      "nProtect",
		Processes: []string{"nspupsvc.exe", "Npkcmsvc.exe", "npnj5Agent.exe"},
		Url:       "http://nos.nprotect.com/",
	}, {
		Name:      "Spyware Terminator",
		Processes: []string{"SpywareTerminatorShield.exe", "SpywareTerminator.exe"},
		Url:       "http://www.spywareterminator.com/Default.aspx",
	}, {
		Name:      "Norton",
		Processes: []string{"ccSvcHst.exe", "rtvscan.exe", "ccapp.exe", "NPFMntor.exe", "ccRegVfy.exe", "vptray.exe", "iamapp.exe", "nav.exe", "navapw32.exe", "navapsvc.exe", "nisum.exe", "nmain.exe", "nprotect.exe", "smcGui.exe", "alertsvc.exe"},
		Url:       "https://us.norton.com/",
	}, {
		Name:      "可牛杀毒",
		Processes: []string{"knsdtray.exe"},
		Url:       "https://baike.baidu.com/item/%E5%8F%AF%E7%89%9B%E5%85%8D%E8%B4%B9%E6%9D%80%E6%AF%92%E8%BD%AF%E4%BB%B6",
	}, {
		Name:      "流量矿石",
		Processes: []string{"Miner.exe"},
		Url:       "https://jiaoyi.yunfan.com/",
	}, {
		Name:      "safedog",
		Processes: []string{"safedog.exe", "SafeDogGuardCenter.exe", "safedogupdatecenter.exe", "safedogguardcenter.exe", "SafeDogSiteIIS.exe", "SafeDogTray.exe", "SafeDogServerUI.exe"},
		Url:       "http://www.safedog.cn/",
	}, {
		Name:      "木马克星",
		Processes: []string{"parmor.exe", "Iparmor.exe"},
		Url:       "https://baike.baidu.com/item/%E6%9C%A8%E9%A9%AC%E5%85%8B%E6%98%9F/2979824?fr=aladdin",
	}, {
		Name:      "贝壳云安全",
		Processes: []string{"beikesan.exe"},
		Url:       "",
	}, {
		Name:      "木马猎手",
		Processes: []string{"TrojanHunter.exe"},
		Url:       "",
	}, {
		Name:      "巨盾网游安全盾",
		Processes: []string{"GG.exe"},
		Url:       "",
	}, {
		Name:      "绿鹰安全精灵",
		Processes: []string{"adam.exe"},
		Url:       "https://baike.baidu.com/item/%E7%BB%BF%E9%B9%B0%E5%AE%89%E5%85%A8%E7%B2%BE%E7%81%B5",
	}, {
		Name:      "超级巡警",
		Processes: []string{"AST.exe"},
		Url:       "",
	}, {
		Name:      "墨者安全专家",
		Processes: []string{"ananwidget.exe"},
		Url:       "",
	}, {
		Name:      "风云防火墙",
		Processes: []string{"FYFireWall.exe"},
		Url:       "",
	}, {
		Name:      "微点主动防御",
		Processes: []string{"MPMon.exe"},
		Url:       "http://www.micropoint.com.cn/",
	}, {
		Name:      "天网防火墙",
		Processes: []string{"pfw.exe"},
		Url:       "",
	}, {
		Name:      "D 盾",
		Processes: []string{"D_Safe_Manage.exe", "d_manage.exe"},
		Url:       "http://www.d99net.net/",
	}, {
		Name:      "云锁",
		Processes: []string{"yunsuo_agent_service.exe", "yunsuo_agent_daemon.exe"},
		Url:       "https://www.yunsuo.com.cn/",
	}, {
		Name:      "护卫神",
		Processes: []string{"HwsPanel.exe", "hws_ui.exe", "hws.exe", "hwsd.exe"},
		Url:       "https://www.hws.com/",
	}, {
		Name:      "火绒安全",
		Processes: []string{"hipstray.exe", "HipsTray.exe", "wsctrl.exe", "usysdiag.exe", "HipsDaemon.exe", "HipsLog.exe", "HipsMain.exe", "wsctrl.exe"},
		Url:       "https://www.huorong.cn/",
	}, {
		Name:      "网络病毒克星",
		Processes: []string{"WEBSCANX.exe"},
		Url:       "",
	}, {
		Name:      "SPHINX防火墙",
		Processes: []string{"SPHINX.exe"},
		Url:       "",
	}, {
		Name:      "Enhanced Mitigation Experience Toolkit",
		Processes: []string{"emet_agent.exe", "emet_service.exe"},
		Url:       "https://www.microsoft.com/",
	}, {
		Name:      "H+BEDV Datentechnik GmbH",
		Processes: []string{"avwin.exe", "avwupsrv.exe"},
		Url:       "http://www.free-av.com/",
	}, {
		Name:      "IBM ISS Proventia",
		Processes: []string{"blackd.exe", "rapapp.exe"},
		Url:       "",
	}, {
		Name:      "eEye Digital Security",
		Processes: []string{"eeyeevnt.exe", "blink.exe"},
		Url:       "",
	}, {
		Name:      "TamoSoft",
		Processes: []string{"cv.exe", "ent.exe"},
		Url:       "https://www.tamos.com/",
	}, {
		Name:      "Kerio Personal Firewall",
		Processes: []string{"persfw.exe", "wrctrl.exe"},
		Url:       "http://www.kerio.com/",
	}, {
		Name:      "Simplysup",
		Processes: []string{"Trjscan.exe"},
		Url:       "https://www.simplysup.com/",
	}, {
		Name:      "PC Tools AntiVirus",
		Processes: []string{"PCTAV.exe", "pctsGui.exe"},
		Url:       "http://www.pctools.com",
	}, {
		Name:      "VirusBuster Professional",
		Processes: []string{"vbcmserv.exe"},
		Url:       "http://www.virusbuster.hu",
	}, {
		Name:      "ClamWin",
		Processes: []string{"ClamTray.exe", "clamscan.exe"},
		Url:       "http://www.clamwin.com/",
	}, {
		Name:      "安天智甲",
		Processes: []string{"kxetray.exe", "kscan.exe", "AMediumManager.exe", "kismain.exe"},
		Url:       "https://antiy.cn/",
	}, {
		Name:      "CMC Endpoint Security",
		Processes: []string{"CMCNECore.exe", "cmcepagent.exe", "cmccore.exe", "CMCLog.exe", "CMCFMon.exe"},
		Url:       "https://cmccybersecurity.com/giai-phap/",
	}, {
		Name:      "金山毒霸",
		Processes: []string{"kxescore.exe", "kupdata.exe", "kxetray.exe", "kwsprotect64.exe"},
		Url:       "http://www.ijinshan.com/",
	}, {
		Name:      "Agnitum outpost",
		Processes: []string{"outpost.exe", "acs.exe"},
		Url:       "https://agnitum-outpost-security-suite.en.softonic.com/",
	}, {
		Name:      "Cynet",
		Processes: []string{"CynetLauncher.exe", "CynetDS.exe", "CynetEPS.exe", "CynetMS.exe", "CynetAR.exe", "CynetGW.exe", "CynetSD64.exe"},
		Url:       "https://www.cynet.com/",
	}, {
		Name:      "Elastic",
		Processes: []string{"winlogbeat.exe"},
		Url:       "https://www.elastic.co/",
	}, {
		Name:      "MaxSecure",
		Processes: []string{"MaxAVPlusDM.exe", "MaxRCSystemTray.exe", "RCSystemTray.exe", "SDSystemTray.exe", "LiveUpdateSD.exe"},
		Url:       "https://maxsecureantivirus.com/",
	}, {
		Name:      "Lavasoft杀毒",
		Processes: []string{"ad-watch.exe"},
		Url:       "https://www.adaware.com/",
	}, {
		Name:      "卡巴斯基",
		Processes: []string{"rescue32.exe", "_avp32.exe", "_avpcc.exe", "_avpm.exe"},
		Url:       "https://www.kaspersky.com.cn/",
	}, {
		Name:      "AntiTrojanElite",
		Processes: []string{"anti-trojan.exe"},
		Url:       "http://www.remove-trojan.com/",
	}, {
		Name:      "未知",
		Processes: []string{"ackwin32.exe"},
		Url:       "",
	},
}

// 存放demo数据
var Demo = []AvType{
	{
		Name:      "demo",
		Processes: []string{"demo.exe", "demo1.exe", "demo2.exe", "demo3.exe"},
		Url:       "https://www.demo.com/",
	}, {
		Name:      "test",
		Processes: []string{"test.exe", "test1.exe", "test2.exe", "test3.exe"},
		Url:       "https://www.test.cn/",
	},
}
