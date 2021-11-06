package vita.misc;

import java.util.HashMap;
import java.util.Map;

//Used to manipulate names
public final class NameUtil {
	private Map<String, String> MODULE_NAME_TO_FILE_NAME_MAP;
	private Map<String, String> LIBRARY_NAME_TO_MODULE_NAME_MAP;
			
	private static NameUtil INSTANCE = new NameUtil();
	
	private NameUtil() {
		MODULE_NAME_TO_FILE_NAME_MAP = new HashMap<>();
	//os0: modules
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSblACMgr","acmgr.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSblAuthMgr","authmgr.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceKernelBusError","buserror.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceCrashDump","crashdump.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceDisplay","display.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceKernelDmacMgr","dmacmgr.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceEnumWakeUp","enum_wakeup.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceExcpmgr","excpmgr.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceExfatfs","exfatfs.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSblGcAuthMgr","gcauthmgr.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceGpuEs4CoreDump","gpucoredump_es4.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceHdmi","hdmi.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceKernelIntrMgr","intrmgr.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceIofilemgr","iofilemgr.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceKrm","krm.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLcd","lcd.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLowio","lowio.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceMagicGate","magicgate.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceMarlinHci","marlin_hci.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSblMgKeyMgr","mgkeymgr.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceMgVideo","mgvideo.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceKernelModulemgr","modulemgr.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceMsif","msif.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceOled","oled.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSblPcbcBin","pcbc.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceProcessmgr","processmgr.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceRtc","rtc.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSdif","sdif.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSdstor","sdstor.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSblSmschedProxy","smsc_proxy.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSblSsSmComm","sm_comm.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSblSsMgr","ss_mgr.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSyscon","syscon.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSysmem","sysmem.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSysStateMgr","sysstatemgr.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSystimer","systimer.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceKernelThreadMgr","threadmgr.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceUsbDevSerial","usbdev_serial.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceUsbPspcm","usbpspcm.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceUsbstorDriver","usbstor.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceUsbstorMg","usbstormg.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceUsbstorVStorDriver","usbstorvstor.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceVipImage","vipimg.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceVeneziaImage","vnzimg.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceWlanBtRobinImageAx","wlanbt_robin_img_ax.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceAppMgr","appmgr.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceAudio","audio.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceAudioin","audioin.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceAvcodec","avcodec.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceAVConfig","av_config.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceBbmc","bbmc.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceBt","bt.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceCamera","camera.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceCameraDummy","camera_dummy.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceClockgen","clockgen.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceCodec","codec.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceCodec","codec_cx.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceCompat","compat.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceCoredump","coredump.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceCtrl","ctrl.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceDs3","ds3.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceError","error.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceFios2Kernel","fios2.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceGps","gps.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceGpuEs4Init","gpuinit_es4.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceGpuEs4","gpu_es4.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceHid","hid.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceHpremote","hpremote.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceIdStorage","idstorage.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceKrm","krm.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceMotionDev","motion.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceMotionDevDummy","motion_dummy.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceMtpIfDriver","mtpif.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNetPs","net_ps.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNgs","ngs.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpDrm","npdrm.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("ScePfsMgr","pfsmgr.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSblPostSsMgr","post_ss_mgr.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("ScePower","power.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceRegistryMgr","regmgr.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSysmodule","sysmodule.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceTouch","touch.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceTouchDummy","touch_dummy.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceTty2uart","tty2uart.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceUdcd","udcd.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceUlobjMgr","ulobjmgr.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceUsbMass","umass.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSblUpdateMgr","update_mgr.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceUsbAudio","usbaudio.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceUsbd","usbd.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceUsbMtp","usbmtp.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceUsbPspcm","usbpspcm.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceUsbSerial","usbserial.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceUsbServ","usbserv.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceUsbstorDriver","usbstor.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceUsbstorVStorDriver","usbstorvstor.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceUsbEtherRtl","usb_ether_rtl.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceUsbEtherSmsc","usb_ether_smsc.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceCodecEngineWrapper","vnz_wrapper.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceVshBridge","vshbridge.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceWlanBt","wlanbt.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSafeMode","safemode.self");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceAvcodecUser","avcodec_us.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceDriverUser","driver_us.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceGpuEs4User","libgpu_es4.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceGxm","libgxm_es4.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibKernel","libkernel.suprx");
			
	//vs0: modules
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpPartyAppUtil","np_party_app.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSecondScreen","libSceSecondScreen.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSystemSettingsCore","system_settings_core.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceTelReg","tel_reg.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSblPcffBin","pcff.skprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceGriefReportDialog","grief_report_dialog.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceEmailEngine","email_engine.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("fake_package_installer_spa","spawn.self"); //NPXS10082
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceStitcherCoreAdapter","stitch_core_prx.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceStitchAdapter","stitch_prx.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("gaikai_player","gaikai-player.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceWebFiltering","jx_web_filtering.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("ScePsp2Compat","ScePsp2Compat.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceWebKit","SceWebKitModule.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibVitaJSExtObj","vita_jsextobj.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceActivityDb","activity_db.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNetAdhocMatching","adhoc_matching.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceAppUtil","apputil.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceAppUtilExt","apputil_ext.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceAudiocodec","audiocodec.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceAvcdecForPlayer","avcdec_for_player.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceBgAppUtil","bgapputil.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("ScebXCe","bXCe.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceCommonGuiDialog","common_gui_dialog.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceDbrecoveryUtility","dbrecovery_utility.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceDbutil","dbutil.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceFriendSelect","friend_select.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceIncomingDialog","incoming_dialog.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceIniFileProcessor","ini_file_processor.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceAtrac","libatrac.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibc","libc.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceCommonDialog","libcdlg.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceCalendarDialogPlugin","libcdlg_calendar_review.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceCamImportDialogPlugin","libcdlg_cameraimport.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceCheckoutDialogPlugin","libcdlg_checkout.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceCompanionDialogPlugin","libcdlg_companion.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceCompatDialogPlugin","libcdlg_compat.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceCrossCtlDialogPlugin","libcdlg_cross_controller.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceFriendListDialogPlugin","libcdlg_friendlist.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceFriendList2DialogPlugin","libcdlg_friendlist2.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpGameCustomDataDPlugin","libcdlg_game_custom_data.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpGameCustomDataDlgImpl","libcdlg_game_custom_data_impl.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceImeDialogPlugin","libcdlg_ime.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceInvitationDlgPlugin","libcdlg_invitation.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceInvitationDlgImplPlugin","libcdlg_invitation_impl.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceCommonDialogMain","libcdlg_main.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceMsgDialogPlugin","libcdlg_msg.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNearDialogPlugin","libcdlg_near.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNetCheckDialogPlugin","libcdlg_netcheck.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpEulaDialogPlugin","libcdlg_npeula.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpProfile2DialogPlugin","libcdlg_npprofile2.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpMessageDialogPlugin","libcdlg_np_message.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpSnsFbDialogPlugin","libcdlg_np_sns_fb.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceTrophySetupDialogPlugin","libcdlg_np_trophy_setup.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("ScePhotoImportDialogPlugin","libcdlg_photoimport.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("ScePhotoReviewDialogPlugin","libcdlg_photoreview.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("ScePocsDialogPlugin","libcdlg_pocketstation.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceRemoteOSKDialogPlugin","libcdlg_remote_osk.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSaveDataDialogPlugin","libcdlg_savedata.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceTwitterDialogPlugin","libcdlg_twitter.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceTwLoginDialogPlugin","libcdlg_tw_login.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceVideoImportDialogPlugin","libcdlg_videoimport.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceClipboard","libclipboard.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibDbg","libdbg.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceFiber","libfiber.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibFios2","libfios2.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibG729","libg729.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibGameUpdate","libgameupdate.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceHandwriting","libhandwriting.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibHttp","libhttp.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceIme","libime.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceIpmiNonGameApp","libipmi_nongame.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibLocation","liblocation.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibLocationExtension","liblocation_extension.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibLocationFactory","liblocation_factory.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibLocationInternal","liblocation_internal.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibMarlin","libmln.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("MarlinAppLib","libmlnapplib.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceMarlinDownloader","libmlndownloader.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceAacenc","libnaac.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNet","libnet.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibNetCtl","libnetctl.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNgsUser","libngs.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("ScePaf","libpaf.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("ScePafWebMapView","libpaf_web_map_view.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("ScePerf","libperf.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibPgf","libpgf.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibPvf","libpvf.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibRudp","librudp.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSasUser","libsas.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceAvPlayer","libsceavplayer.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceBeisobmf","libSceBeisobmf.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceBemp2sys","libSceBemp2sys.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceCompanionUtil","libSceCompanionUtil.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceDtcpIp","libSceDtcpIp.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibft2","libSceFt2.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceJpegArm","libscejpegarm.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceJpegEncArm","libscejpegencarm.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibJson","libSceJson.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceMp4","libscemp4.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibMp4Recorder","libSceMp4Rec.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceMusicExport","libSceMusicExport.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNearDialogUtil","libSceNearDialogUtil.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNearUtil","libSceNearUtil.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("ScePhotoExport","libScePhotoExport.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("ScePromoterUtil","libScePromoterUtil.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceScreenShot","libSceScreenShot.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceShutterSound","libSceShutterSound.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSqlite","libSceSqlite.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceTelephonyUtil","libSceTelephonyUtil.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceTeleportClient","libSceTeleportClient.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceTeleportServer","libSceTeleportServer.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceVideoExport","libSceVideoExport.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceVideoSearchEmpr","libSceVideoSearchEmpr.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibXml","libSceXml.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceShellSvc","libshellsvc.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibSsl","libssl.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSulpha","libsulpha.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSystemGesture","libsystemgesture.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceUlt","libult.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceVoice","libvoice.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceVoiceQoS","libvoiceqos.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLiveAreaUtil","livearea_util.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("mail_api_for_local_libc","mail_api_for_local_libc.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNearProfile","near_profile.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNotificationUtil","notification_util.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpActivityNet","np_activity.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpActivity","np_activity_sdk.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpBasic","np_basic.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpCommerce2","np_commerce2.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpCommon","np_common.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpCommonPs4","np_common_ps4.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpFriendPrivacyLevel","np_friend_privacylevel.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpKdc","np_kdc.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpManager","np_manager.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpMatching2","np_matching2.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpMessage","np_message.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpMessageContactsPlugin","np_message_contacts.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpMessageDlgImplPlugin","np_message_dialog_impl.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpMessagePadding","np_message_padding.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpPartyGameUtil","np_party.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpScore","np_ranking.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpSignaling","np_signaling.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpSnsFacebook","np_sns_facebook.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpTrophy","np_trophy.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpTus","np_tus.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpUtility","np_utility.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpWebApi","np_webapi.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("ScePartyMemberListPlugin","party_member_list.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceDrmPsmKdc","psmkdc.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibPspnetAdhoc","pspnet_adhoc.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSignInExt","signin_ext.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSqliteVsh","sqlite.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceStoreCheckoutPlugin","store_checkout_plugin.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceTriggerUtil","trigger_util.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceWebUIPlugin","web_ui_plugin.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceAppSettings","app_settings.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceAuthPlugin","auth_plugin.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceAvContentHandler","av_content_handler.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceBackupRestore","backup_restore.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceContentOperation","content_operation.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceDbRecovery","dbrecovery_plugin.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceDbSetup","dbsetup.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceBEAVCorePlayer","libBEAVCorePlayer.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibFflMp4","libFflMp4.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibical","libical.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibicalss","libicalss.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibMarlin","libmarlin.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceMarlinDownloader","libmarlindownloader.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibMarlinPb","libmarlin_pb.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibMtp","libmtp.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibMtpHttp","libmtphttp.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibMtpHttpWrapper","libmtphttp_wrapper.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibFflVuMp4","libSenvuabsFFsdk.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceVideoProfiler","libvideoprofiler.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("mail_api_for_local","mail_api_for_local.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceMtpr3","mtpr3.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceMtpClient","mtp_client.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceNpGriefReport","np_grief_report.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceAACPromoter","AACPromoter.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceBmpPromoter","bmp_promoter.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceGifPromoter","gif_promoter.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceJpegPromoter","jpeg_promoter.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceMetaGen","meta_gen.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceMp3Promoter","Mp3Promoter.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceMsvPromoter","MsvPromoter.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("ScePngPromoter","png_promoter.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceRiffPromoter","RiffPromoter.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceSensMe","SensMe.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceTiffPromoter","tiff_promoter.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceGameCardInstallerPlugin","gamecard_installer_plugin.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceGameDataPlugin","gamedata_plugin.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceInitialSetup","initialsetup.self");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceOnlineStoragePlugin","online_storage_plugin.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceAuthResetPlugin","auth_reset_plugin.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceIduUpdate","idu_update_plugin.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceImePlugin","ime_plugin.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceImposeNet","impose_net_plugin.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibLocationDolceProvide","liblocation_dolce_provider.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibLocationPermission","liblocation_permission.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLibLocationProvider","liblocation_provider.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLsdb","livespace_db.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceLocationPlugin","location_dialog_plugin.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceTelInitialCheck","tel_initial_check_plugin.suprx");
			MODULE_NAME_TO_FILE_NAME_MAP.put("SceShell","shell.self");
			
		LIBRARY_NAME_TO_MODULE_NAME_MAP = new HashMap<>();
		
	//os0: modules
			//psp2config_dolce.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceKernelPsp2Config", "SceKernelPsp2Config");
			//psp2config_vita.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceKernelPsp2Config", "SceKernelPsp2Config");
			
		//kd modules
			//acmgr.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblACMgrForKernel", "SceSblACMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblACMgrForDriver", "SceSblACMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblACMgr", "SceSblACMgr");
			//authmgr.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblAuthMgrForKernel", "SceSblAuthMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblAuthMgrForDriver", "SceSblAuthMgr");
			//buserror.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceBusErrorForKernel", "SceKernelBusError");
			//display.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceDisplayForDriver", "SceDisplay");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceDisplay", "SceDisplay");
			//dmacmgr.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceDmacmgrForDriver", "SceKernelDmacMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceDmacmgr", "SceKernelDmacMgr");
			//excpmgr.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceExcpmgrForKernel", "SceExcpmgr");
			//gcauthmgr.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblGcAuthMgrDrmBBForDriver", "SceSblGcAuthMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblGcAuthMgrGcAuthForDriver", "SceSblGcAuthMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblGcAuthMgrMlnpsnlForDriver", "SceSblGcAuthMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblGcAuthMgrPkgForDriver", "SceSblGcAuthMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblGcAuthMgrPsmactForDriver", "SceSblGcAuthMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblGcAuthMgrSclkForDriver", "SceSblGcAuthMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblGcAuthMgrMsSaveBBForDriver", "SceSblGcAuthMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblGcAuthMgr", "SceSblGcAuthMgr");
			//hdmi.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceHdmiForDriver", "SceHdmi");
			//intrmgr.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceIntrmgrForKernel", "SceKernelIntrMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceIntrmgrForDriver", "SceKernelIntrMgr");
			//iofilemgr.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceIofilemgrForDriver", "SceIofilemgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceIofilemgr", "SceIofilemgr");
			//krm.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceKrm", "SceKrm");
			//lcd.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLcdForDriver", "SceLcd");
			//lowio.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePervasiveForDriver", "SceLowio");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceGpioForDriver", "SceLowio");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePwmForDriver", "SceLowio");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceI2cForDriver", "SceLowio");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceGrabForDriver", "SceLowio");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceCdramForDriver", "SceLowio");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceDsiForDriver", "SceLowio");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceIftuForDriver", "SceLowio");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceCsiForDriver", "SceLowio");
			//magicgate.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceMagicGateForDriver", "SceMagicGate");
			//marlin_hci.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceMarlinHci", "SceMarlinHci");
			//mgkeymgr.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblMgKeyMgrForDriver", "SceSblMgKeyMgr");
			//mgvideo.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceMgVideo", "SceMgVideo");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceMgVideoForMiniApp", "SceMgVideo");
			//modulemgr.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceModulemgrForKernel", "SceKernelModulemgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceModulemgrForDriver", "SceKernelModulemgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceModulemgr", "SceKernelModulemgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceBacktraceForDriver", "SceKernelModulemgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceBacktrace", "SceKernelModulemgr");
			//msif.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceMsifForDriver", "SceMsif");
			//oled.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceOledForDriver", "SceOled");
			//processmgr.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceProcessmgr", "SceProcessmgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceProcessmgrForDriver", "SceProcessmgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceProcessmgrForKernel", "SceProcessmgr");
			//rtc.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceRtcForDriver", "SceRtc");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceRtc", "SceRtc");
			//sdif.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSdifForDriver", "SceSdif");
			//smsc_proxy.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblSmSchedProxyForKernel", "SceSblSmschedProxy");
			//sm_comm.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblSmCommForKernel", "SceSblSsSmComm");
			//ss_mgr.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblSsMgrForKernel", "SceSblSsMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblSsMgrForDriver", "SceSblSsMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblQafMgr", "SceSblSsMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblRng", "SceSblSsMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblDmac5Mgr", "SceSblSsMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblAimgr", "SceSblSsMgr");
			//syscon.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSysconForDriver", "SceSyscon");
			//sysmem.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSysmemForKernel", "SceSysmem");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSysmemForDriver", "SceSysmem");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSysmem", "SceSysmem");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceDebugLed", "SceSysmem");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceDebugLedForDriver", "SceSysmem");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceDipsw", "SceSysmem");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceDipswForDriver", "SceSysmem");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceUartForKernel", "SceSysmem");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceDebugForKernel", "SceSysmem");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceDebugForDriver", "SceSysmem");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSysclibForDriver", "SceSysmem");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSysrootForKernel", "SceSysmem");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceKernelUtilsForDriver", "SceSysmem");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceKernelSuspendForDriver", "SceSysmem");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceQafMgrForDriver", "SceSysmem");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePmMgrForDriver", "SceSysmem");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblAIMgrForDriver", "SceSysmem");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceProcEventForDriver", "SceSysmem");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSysrootForDriver", "SceSysmem");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceCpu", "SceSysmem");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceCpuForKernel", "SceSysmem");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceCpuForDriver", "SceSysmem");
			//systimer.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSystimerForDriver", "SceSystimer");
			//threadmgr.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceThreadmgrForKernel", "SceKernelThreadMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceThreadmgrForDriver", "SceKernelThreadMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceThreadmgr", "SceKernelThreadMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceThreadmgrCoredumpTime", "SceKernelThreadMgr");
			//usbdev_serial.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceUsbDevSerial", "SceUsbDevSerial");
			//usbpspcm.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceUsbPspcm", "SceUsbPspcm");
			//usbstor.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceUsbstorForDriver", "SceUsbstorDriver");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceUsbstor", "SceUsbstorDriver");
			//usbstormg.skprx
			//usbstorvstor.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceUsbstorVStor", "SceUsbstorVStorDriver");
			
		//bootimage.skprx embedded modules
			//appmgr.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAppMgrForDriver", "SceAppMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAppMgr", "SceAppMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSharedFb", "SceAppMgr");
			//audio.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAudioForDriver", "SceAudio");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAudio", "SceAudio");
			//audioin.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAudioInForDriver", "SceAudioin");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAudioIn", "SceAudioin");
			//avcodec.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAvcodecForDriver", "SceAvcodec");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAvcodec", "SceAvcodec");
			//av_config.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAVConfigForDriver", "SceAVConfig");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAVConfig", "SceAVConfig");
			//bbmc.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceBbmcForDriver", "SceBbmc");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceBbmc", "SceBbmc");
			//bt.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceBtForDriver", "SceBt");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceBt", "SceBt");
			//camera.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceCameraForDriver", "SceCamera");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceCamera", "SceCamera");
			
			//camera_dummy.skprx - commented out as it's unintresting
			//LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceCameraForDriver", "SceCameraDummy");
			//LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceCamera", "SceCameraDummy");
			
			//clockgen.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceClockgenForDriver", "SceClockgen");
			//codec.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceCodecForDriver", "SceCodec");
			//codec_cx.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceCodecForDriver", "SceCodec");
			//compat.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceCompat", "SceCompat");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceCompatForVsh", "SceCompat");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceCompatForDriver", "SceCompat");
			//coredump.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceCoredumpForDriver", "SceCoredump");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceCoredump", "SceCoredump");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceCoredumpNounlink", "SceCoredump");
			//ctrl.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceCtrlForDriver", "SceCtrl");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceCtrl", "SceCtrl");
			//error.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceError", "SceError");
			//fios2.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceFios2KernelForDriver", "SceFios2Kernel");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceFios2Kernel", "SceFios2Kernel");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceFios2Kernel02", "SceFios2Kernel");
			//gps.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceGpsForDriver", "SceGps");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceGps", "SceGps");
			//gpu_es4.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceGpuEs4ForDriver", "SceGpuEs4");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceGpuEs4ForUser", "SceGpuEs4");
			//hid.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceHidForDriver", "SceHid");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceHid", "SceHid");
			//hpremote.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceHpremoteForDriver", "SceHpremote");
			//idstorage.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceIdStorageForDriver", "SceIdStorage");
			//krm.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceKrm", "SceKrm");
			//motion.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceMotionDev", "SceMotionDev");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceMotionDevForDriver", "SceMotionDev");
			
			//motion_dummy.skprx - commented out as it's unintresting
			//LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceMotionDev", "SceMotionDevDummy");
			//LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceMotionDevForDriver", "SceMotionDevDummy");
			
			//mtpif.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceMtpIfForDriver", "SceMtpIfDriver");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceMtpIf", "SceMtpIfDriver");
			//net_ps.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNetPsForDriver", "SceNetPs");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNetPsForSyscalls", "SceNetPs");
			//ngs.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNgsInternal", "SceNgs");
			//npdrm.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpDrmForDriver", "SceNpDrm");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpDrm", "SceNpDrm");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePsmDrmForDriver", "SceNpDrm");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePsmDrm", "SceNpDrm");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpDrmPackage", "SceNpDrm");
			//pfsmgr.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePfsMgrForKernel", "ScePfsMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePfsFacadeForKernel", "ScePfsMgr");
			//post_ss_mgr.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblPostSsMgrForDriver", "SceSblPostSsMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceZlibForDriver", "SceSblPostSsMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblPmMgr", "SceSblPostSsMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblRtcMgr", "SceSblPostSsMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblLicMgr", "SceSblPostSsMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblUtMgr", "SceSblPostSsMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblFwLoaderForDriver", "SceSblPostSsMgr");
			//power.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePower", "ScePower");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePowerForDriver", "ScePower");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLedForDriver", "ScePower");
			//regmgr.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceRegMgrForDriver", "SceRegistryMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceRegMgrServiceForDriver", "SceRegistryMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceRegMgr", "SceRegistryMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceRegMgrService", "SceRegistryMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceRegMgrForGame", "SceRegistryMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceRegMgrForSDK", "SceRegistryMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceRegMgrForDebugger", "SceRegistryMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceRegMgrForTool", "SceRegistryMgr");
			//sysmodule.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSysmodule", "SceSysmodule");
			//touch.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceTouch", "SceTouch");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceTouchForDriver", "SceTouch");
			
			//touch_dummy.skprx - commented out as it's unintresting
			//LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceTouch", "SceTouchDummy");
			//LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceTouchForDriver", "SceTouchDummy");

			//udcd.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceUdcd", "SceUdcd");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceUdcdForDriver", "SceUdcd");
			//ulobjmgr.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceUlobjMgr", "SceUlobjMgr");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceUlobjMgrForDriver", "SceUlobjMgr");
			//umass.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceUsbMassForDriver", "SceUsbMass");
			//update_mgr.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSblSsUpdateMgr", "SceSblUpdateMgr");
			//usbaudio.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceUsbAudioForDriver", "SceUsbAudio");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceUsbAudioIn", "SceUsbAudio");
			//usbd.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceUsbdForUser", "SceUsbd");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceUsbdForDriver", "SceUsbd");
			//usbmtp.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceUsbMtpForDriver", "SceUsbMtp");
			//usbpspcm.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceUsbPspcm", "SceUsbPspcm");
			//usbserial.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceUsbSerial", "SceUsbSerial");
			//usbserv.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceUsbServForDriver", "SceUsbServ");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceUsbServ", "SceUsbServ");
			//usbstor.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceUsbstorForDriver", "SceUsbstorDriver");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceUsbstor", "SceUsbstorDriver");
			//usbstorvstor.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceUsbstorVStor", "SceUsbstorVStorDriver");
			//usb_ether_rtl.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceUsbEtherRtlForDriver", "SceUsbEtherRtl");
			//vnz_wrapper.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceCodecEngineWrapperForDriver", "SceCodecEngineWrapper");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceCodecEngineWrapperForDebugger", "SceCodecEngineWrapper");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceCodecEngineWrapper", "SceCodecEngineWrapper");
			//vshbridge.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceVshBridge", "SceVshBridge");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceDrmBridge", "SceVshBridge");
			//wlanbt.skprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceWlanBtForDriver", "SceWlanBt");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceWlan", "SceWlanBt");
			
		//us modules
			//avcodec_us.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAudiodecUser", "SceAvcodecUser");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAudioencUser", "SceAvcodecUser");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceJpegUser", "SceAvcodecUser");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceJpegEncUser", "SceAvcodecUser");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceVideodecUser", "SceAvcodecUser");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceVideoencUser", "SceAvcodecUser");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceVideodecAsyncUser", "SceAvcodecUser");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceVideodecRecoveryPointUser", "SceAvcodecUser");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceVideodecLowDelayUser", "SceAvcodecUser");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceCodecEngineUser", "SceAvcodecUser");
			//driver_us.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceFios2User", "SceDriverUser");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceRtcUser", "SceDriverUser");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceDisplayUser", "SceDriverUser");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceErrorUser", "SceDriverUser");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceMotion", "SceDriverUser");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAppMgrUser", "SceDriverUser");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceDrmBridgeUser", "SceDriverUser");
			//libgpu_es4.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceGpuEs4User", "SceGpuEs4User");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceGpuEs4UserForVsh", "SceGpuEs4User");
			//libgxm_es4.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceGxm", "SceGxm");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceGxmInternal", "SceGxm");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceGxmInternalForGles", "SceGxm");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceGxmInternalForReplay", "SceGxm");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceGxmInternalForTest", "SceGxm");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceGxmInternalForVsh", "SceGxm");
			//libkernel.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLibKernel", "SceLibKernel");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLibGcc", "SceLibKernel");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLibSsp", "SceLibKernel");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceRtabi", "SceLibKernel");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceKernelForVM", "SceLibKernel");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLibRng", "SceLibKernel");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceKernelForMono", "SceLibKernel");
			
	//vs0 modules
		//app modules
			//NPXS10001\np_party_app.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpPartyAppUtil", "SceNpPartyAppUtil");
			//NPXS10013\gaikai-player.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("gaikai_player", "gaikai_player");
			//NPXS10013\libSceSecondScreen.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSecondScreen", "SceSecondScreen");
			//NPXS10015\system_settings_core.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSystemSettingsCore", "SceSystemSettingsCore");
			//NPXS10065\grief_report_dialog.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceGriefReportDialog", "SceGriefReportDialog");
			//NPXS10072\email_engine.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceEmailEngine", "SceEmailEngine");
			//NPXS10095\stitch_core_prx.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceStitcherCoreAdapter", "SceStitcherCoreAdapter");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("stitch_core_prx", "SceStitcherCoreAdapter");
			//NPXS10095\stitch_prx.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceStitchAdapter", "SceStitchAdapter");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("stitch_prx", "SceStitchAdapter");
			//NPXS10098\gaikai-player.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("gaikai_player", "gaikai_player");
		//data\external modules
			//webcore\jx_web_filtering.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceWebFiltering", "SceWebFiltering");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("WebPlugin", "SceWebFiltering");
			//webcore\ScePsp2Compat.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePsp2Compat", "ScePsp2Compat");
			//webcore\SceWebKitModule.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceWebKit", "SceWebKit");
			//webcore\vita_jsextobj.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLibVitaJSExtObj", "SceLibVitaJSExtObj");
		//sys\external modules
			//activity_db.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceActivityDb", "SceActivityDb");
			//adhoc_matching.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNetAdhocMatching", "SceNetAdhocMatching");
			//apputil.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAppUtil", "SceAppUtil");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAppUtilDevice", "SceAppUtil");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAppUtilCache", "SceAppUtil");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAppUtilUmass", "SceAppUtil");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAppUtilWebBrowserCBLimited", "SceAppUtil");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAppUtilNpSignin", "SceAppUtil");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAppUtilBook", "SceAppUtil");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAppUtilLaunchApp", "SceAppUtil");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAppUtilAddcontForce", "SceAppUtil");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAppUtilPsm", "SceAppUtil");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAppUtilAppEventUserDefined", "SceAppUtil");
			//apputil_ext.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAppUtilExt", "SceAppUtilExt");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAppUtilExtPlayReady", "SceAppUtilExt");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAppUtilExtMarlinIptv", "SceAppUtilExt");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAppUtilExtPsNow", "SceAppUtilExt");
			//audiocodec.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAudiocodec", "SceAudiocodec");
			//avcdec_for_player.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAvcdecForPlayer", "SceAvcdecForPlayer");
			//bgapputil.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceBgAppUtil", "SceBgAppUtil");
			//bXCe.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScebXCe", "ScebXCe");
			//common_gui_dialog.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceCommonGuiDialog", "SceCommonGuiDialog");
			//dbrecovery_utility.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceDbrecoveryUtility", "SceDbrecoveryUtility");
			//dbutil.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceDbutil", "SceDbutil");
			//friend_select.suprx
			//incoming_dialog.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceIncomingDialog", "SceIncomingDialog");
			//ini_file_processor.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceIniFileProcessor", "SceIniFileProcessor");
			//libatrac.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAtrac", "SceAtrac");
			//libc.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLibc", "SceLibc");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLibm", "SceLibc");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLibstdcxx", "SceLibc");
			//libcdlg.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceCommonDialog", "SceCommonDialog");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpWebApiCommonDialog", "SceCommonDialog");
			//libcdlg_main.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceCommonDialogMain", "SceCommonDialogMain");
			//libclipboard.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceClipboard", "SceClipboard");
			//libdbg.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceDbg", "SceLibDbg");
			//libfiber.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceFiber", "SceFiber");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceUlobjDbg", "SceFiber");
			//libfios2.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceFios2", "SceLibFios2");
			//libg729.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceG729", "SceLibG729");
			//libgameupdate.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceGameUpdate", "SceLibGameUpdate");
			//libhandwriting.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceHandwriting", "SceHandwriting");
			//libhttp.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceHttp", "SceLibHttp");
			//libime.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceImeVsh", "SceIme");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceIme", "SceIme");
			//libipmi_nongame.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceIpmiNonGameApp", "SceIpmiNonGameApp");
			//liblocation.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLibLocation", "SceLibLocation");
			//liblocation_extension.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLibLocationExtension", "SceLibLocationExtension");
			//liblocation_factory.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLibLocationFactory", "SceLibLocationFactory");
			//liblocation_internal.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLibLocationInternal", "SceLibLocationInternal");
			//libmln.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceMarlin", "SceLibMarlin");
			//libmlnapplib.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("mlnapplib", "MarlinAppLib");
			//libmlndownloader.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("mlndl", "SceMarlinDownloader");
			//libnaac.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAacencInternal", "SceAacenc");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAacenc", "SceAacenc");
			//libnet.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNet", "SceNet");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNetInternal", "SceNet");
			//libnetctl.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNetCtl", "SceLibNetCtl");
			//libngs.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNgs", "SceNgsUser");
			//libpaf.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePafLowlayer", "ScePaf");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePafStdc", "ScePaf");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePafMisc", "ScePaf");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePafCommon", "ScePaf");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePafGraphics", "ScePaf");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePafThread", "ScePaf");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePafResource", "ScePaf");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePafToplevel", "ScePaf");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePafWidget", "ScePaf");
			//libpaf_web_map_view.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePafWebMapView", "ScePafWebMapView");
			//libperf.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePerf", "ScePerf");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePerfInternal", "ScePerf");
			//libpgf.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePgf", "SceLibPgf");
			//libpvf.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePvf", "SceLibPvf");
			//librudp.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLibRudp", "SceLibRudp");
			//libsas.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSas", "SceSasUser");
			//libsceavplayer.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAvPlayer", "SceAvPlayer");
			//libSceBeisobmf.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceBeisobmf", "SceBeisobmf");
			//libSceBemp2sys.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceBemp2sys", "SceBemp2sys");
			//libSceCompanionUtil.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceCompanionUtil", "SceCompanionUtil");
			//libSceDtcpIp.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceDtcpIp", "SceDtcpIp");
			//libSceFt2.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceFt2", "SceLibft2");
			//libscejpegarm.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceJpegArm", "SceJpegArm");
			//libscejpegencarm.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceJpegEncArm", "SceJpegEncArm");
			//libSceJson.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLibJson", "SceLibJson");
			//libscemp4.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceMp4", "SceMp4");
			//libSceMp4Rec.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLibMp4Recorder", "SceLibMp4Recorder");
			//libSceMusicExport.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceMusicExport", "SceMusicExport");
			//libSceNearDialogUtil.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNearDialogUtil", "SceNearDialogUtil");
			//libSceNearUtil.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNearUtil", "SceNearUtil");
			//libScePhotoExport.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePhotoExport", "ScePhotoExport");
			//libScePromoterUtil.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePromoterUtil", "ScePromoterUtil");
			//libSceScreenShot.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceScreenShot", "SceScreenShot");
			//libSceShutterSound.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceShutterSound", "SceShutterSound");
			//libSceSqlite.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSqlite", "SceSqlite");
			//libSceTelephonyUtil.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceTelephonyUtil", "SceTelephonyUtil");
			//libSceTeleportClient.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceTeleportClient", "SceTeleportClient");
			//libSceTeleportServer.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceTeleportServer", "SceTeleportServer");
			//libSceVideoExport.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceVideoExport", "SceVideoExport");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceVideoExportEmpr", "SceVideoExport");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceVideoExportData", "SceVideoExport");
			//libSceVideoSearchEmpr.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceVideoSearchEmpr", "SceVideoSearchEmpr");
			//libSceXml.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLibXml", "SceLibXml");
			//libshellsvc.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceShellSvc", "SceShellSvc");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceShellUtil", "SceShellSvc");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceShellUtilUketorne", "SceShellSvc");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceShellUtilLaunchApp", "SceShellSvc");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSvcCtrl", "SceShellSvc");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceIpmi", "SceShellSvc");
			//libssl.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSsl", "SceLibSsl");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSslInternal", "SceLibSsl");
			//libsulpha.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSulpha", "SceSulpha");
			//libsystemgesture.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSystemGesture", "SceSystemGesture");
			//libult.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceUlt", "SceUlt");
			//libvoice.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceVoice", "SceVoice");
			//libvoiceqos.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceVoiceQoS", "SceVoiceQoS");
			//livearea_util.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLiveAreaUtil", "SceLiveAreaUtil");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLiveAreaUtilBgApp", "SceLiveAreaUtil");
			//mail_api_for_local_libc.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("mail_api_for_local_libc", "mail_api_for_local_libc");
			//near_profile.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNearProfile", "SceNearProfile");
			//notification_util.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNotificationUtil", "SceNotificationUtil");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNotificationUtilBgApp", "SceNotificationUtil");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNotificationUtilProgress", "SceNotificationUtil");
			//np_activity.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpActivityNet", "SceNpActivityNet");
			//np_activity_sdk.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpActivity", "SceNpActivity");
			//np_basic.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpBasic", "SceNpBasic");
			//np_commerce2.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpCommerce2", "SceNpCommerce2");
			//np_common.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpCommon", "SceNpCommon");
			//np_common_ps4.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpCommonPs4", "SceNpCommonPs4");
			//np_friend_privacylevel.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpFriendPrivacyLevel", "SceNpFriendPrivacyLevel");
			//np_kdc.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpKdc", "SceNpKdc");
			//np_manager.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpManager", "SceNpManager");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpManagerSP", "SceNpManager");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpManagerOAuth", "SceNpManager");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpManagerTicket", "SceNpManager");
			//np_matching2.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpMatching2", "SceNpMatching2");
			//np_message.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpMessage", "SceNpMessage");
			//np_message_contacts.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpMessageContacts", "SceNpMessageContactsPlugin");
			//np_message_dialog_impl.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpMessageDialogPlugin", "SceNpMessageDlgImplPlugin");
			//np_message_padding.suprx
			//np_party.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpPartyGameUtil", "SceNpPartyGameUtil");
			//np_ranking.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpScore", "SceNpScore");
			//np_signaling.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpSignaling", "SceNpSignaling");
			//np_sns_facebook.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpSnsFacebook", "SceNpSnsFacebook");
			//np_trophy.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpTrophy", "SceNpTrophy");
			//np_tus.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpTus", "SceNpTus");
			//np_utility.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpUtility", "SceNpUtility");
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpUtilityAvatarN", "SceNpUtility");
			//np_webapi.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpWebApi", "SceNpWebApi");
			//party_member_list.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePartyMemberListPlugin", "ScePartyMemberListPlugin");
			//psmkdc.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceDrmPsmKdc", "SceDrmPsmKdc");
			//pspnet_adhoc.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePspnetAdhoc", "SceLibPspnetAdhoc");
			//sqlite.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSqliteVsh", "SceSqliteVsh");
			//trigger_util.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceTriggerUtil", "SceTriggerUtil");
			//web_ui_plugin.suprx
			
		//vsh\common modules
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceWebUIPlugin", "SceWebUIPlugin");
			//app_settings.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAppSettings", "SceAppSettings");
			//auth_plugin.suprx
			//av_content_handler.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceHostAvch", "SceAvContentHandler");
			//backup_restore.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceBackupRestore", "SceBackupRestore");
			//content_operation.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceContentOperation", "SceContentOperation");
			//dbrecovery_plugin.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceDbRecovery", "SceDbRecovery");
			//dbsetup.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceDbSetup", "SceDbSetup");
			//libBEAVCorePlayer.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceBEAVCorePlayer", "SceBEAVCorePlayer");
			//libFflMp4.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLibFflMp4", "SceLibFflMp4");
			//libical.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("libical", "SceLibical");
			//libicalss.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("libicalss", "SceLibicalss");
			//libmarlin.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceMarlin", "SceLibMarlin");
			//libmarlindownloader.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("mlndl", "SceMarlinDownloader");
			//libmarlin_pb.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceMarlinPb", "SceLibMarlinPb");
			//libmtp.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLibMtp", "SceLibMtp");
			//libmtphttp.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLibMtpHttp", "SceLibMtpHttp");
			//libmtphttp_wrapper.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLibMtpHttpWrapper", "SceLibMtpHttpWrapper");
			//libSenvuabsFFsdk.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLibFflVuMp4", "SceLibFflVuMp4");
			//libvideoprofiler.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceVideoProfiler", "SceVideoProfiler");
			//mail_api_for_local.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("mail_api_for_local", "mail_api_for_local");
			//mtpr3.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceMtpr3", "SceMtpr3");
			//mtp_client.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceMtpClient", "SceMtpClient");
			//np_grief_report.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceNpGriefReport", "SceNpGriefReport");
		//vsh\common\mms modules
			//AACPromoter.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceAACPromoter", "SceAACPromoter");
			//bmp_promoter.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceBmpPromoter", "SceBmpPromoter");
			//gif_promoter.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceGifPromoter", "SceGifPromoter");
			//jpeg_promoter.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceJpegPromoter", "SceJpegPromoter");
			//meta_gen.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceMetaGen", "SceMetaGen");
			//Mp3Promoter.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceMp3Promoter", "SceMp3Promoter");
			//MsvPromoter.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceMsvPromoter", "SceMsvPromoter");
			//png_promoter.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("ScePngPromoter", "ScePngPromoter");
			//RiffPromoter.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceRiffPromoter", "SceRiffPromoter");
			//SensMe.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceSensMe", "SceSensMe");
			//tiff_promoter.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceTiffPromoter", "SceTiffPromoter");
			
		//vsh\shell modules
			//liblocation_dolce_provider.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLibLocationDolceProvide", "SceLibLocationDolceProvide");
			//liblocation_permission.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLibLocationPermission", "SceLibLocationPermission");
			//liblocation_provider.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLibLocationProvider", "SceLibLocationProvider");
			//livespace_db.suprx
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceLsdb", "SceLsdb");
			//shell.self
			LIBRARY_NAME_TO_MODULE_NAME_MAP.put("SceShell", "SceShell");
	}
	
	public static String getModuleNameFromLibraryName(String libraryName) {
		if (INSTANCE.LIBRARY_NAME_TO_MODULE_NAME_MAP.containsKey(libraryName))
			return INSTANCE.LIBRARY_NAME_TO_MODULE_NAME_MAP.get(libraryName);
		return null;
	}
	
	public static String getFileNameFromModuleName(String moduleName) {
		if (INSTANCE.MODULE_NAME_TO_FILE_NAME_MAP.containsKey(moduleName))
			return INSTANCE.MODULE_NAME_TO_FILE_NAME_MAP.get(moduleName);
		return null;
	}
}
