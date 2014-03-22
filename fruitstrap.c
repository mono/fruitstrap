//TODO: don't copy/mount DeveloperDiskImage.dmg if it's already done - Xcode checks this somehow

#import <CoreFoundation/CoreFoundation.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <stdio.h>
#include <signal.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "MobileDevice.h"

#define FDVENDOR_PATH  "/tmp/fruitstrap-remote-debugserver"
#define PREP_CMDS_PATH "/tmp/fruitstrap-lldb-prep-cmds"
#define LLDB_SHELL "/usr/bin/lldb -s " PREP_CMDS_PATH

#define PRINT(...) do { if (!quiet) printf(__VA_ARGS__); } while (0)

/*
 * Startup script passed to lldb.
 * To see how xcode interacts with lldb, put this into .lldbinit:
 * log enable -v -f /Users/vargaz/lldb.log lldb all
 * log enable -v -f /Users/vargaz/gdb-remote.log gdb-remote all
 *
 * Some things do not seem to work when using the normal commands like process connect/launch, so we invoke them
 * through the python interface.
 */
#define LLDB_PREP_CMDS CFSTR("\
	script fruitstrap_device_app=\"{device_app}\"\n\
	script fruitstrap_connect_url=\"connect://127.0.0.1:12345\"\n\
	platform select remote-ios\n\
	target create \"{disk_app}\"\n\
	script x=lldb.target.modules\n\
    #settings set target.process.extra-startup-command \"QSetLogging:bitmask=LOG_ALL;\"\n \
	script lldb.target.modules[0].SetPlatformFileSpec(lldb.SBFileSpec(fruitstrap_device_app))\n\
	script error=lldb.SBError()\n\
	script lldb.target.Launch(lldb.SBLaunchInfo(None),error)\n\
	script lldb.target.ConnectRemote(lldb.target.GetDebugger().GetListener(),fruitstrap_connect_url,None,error)\n\
")

typedef enum {
    OP_NONE,

    OP_INSTALL,
    OP_UNINSTALL,
    OP_LIST_DEVICES,
    OP_DEBUG,

} operation_t;

typedef struct am_device * AMDeviceRef;
int AMDeviceSecureTransferPath(int zero, AMDeviceRef device, CFURLRef url, CFDictionaryRef options, void *callback, int cbarg);
int AMDeviceSecureInstallApplication(int zero, AMDeviceRef device, CFURLRef url, CFDictionaryRef options, void *callback, int cbarg);
int AMDeviceMountImage(AMDeviceRef device, CFStringRef image, CFDictionaryRef options, void *callback, int cbarg);
int AMDeviceLookupApplications(AMDeviceRef device, int zero, CFDictionaryRef* result);

bool found_device = false, debug = false, verbose = false, quiet = false;
bool wait_with_gdb = false;
bool no_mount = false;
char *app_path = NULL;
char *device_id = NULL;
char *args = NULL;
int timeout = 0;
operation_t operation = OP_INSTALL;
CFStringRef last_path = NULL;
service_conn_t gdbfd;

Boolean path_exists(CFTypeRef path) {
    if (CFGetTypeID(path) == CFStringGetTypeID()) {
        CFURLRef url = CFURLCreateWithFileSystemPath(NULL, path, kCFURLPOSIXPathStyle, true);
        Boolean result = CFURLResourceIsReachable(url, NULL);
        CFRelease(url);
        return result;
    } else if (CFGetTypeID(path) == CFURLGetTypeID()) {
        return CFURLResourceIsReachable(path, NULL);
    } else {
        return false;
    }
}

CFStringRef copy_xcode_dev_path() {
	FILE *fpipe = NULL;
	char *command = "xcode-select -print-path";

	if (!(fpipe = (FILE *)popen(command, "r")))
	{
		perror("Error encountered while opening pipe");
		exit(EXIT_FAILURE);
	}

	char buffer[256] = { '\0' };

	fgets(buffer, sizeof(buffer), fpipe);
	pclose(fpipe);

	strtok(buffer, "\n");
	return CFStringCreateWithCString(NULL, buffer, kCFStringEncodingUTF8);
}

CFStringRef copy_device_support_path(AMDeviceRef device) {
    CFStringRef version = AMDeviceCopyValue(device, 0, CFSTR("ProductVersion"));
    CFStringRef build = AMDeviceCopyValue(device, 0, CFSTR("BuildVersion"));
    const char* home = getenv("HOME");
    CFStringRef path;
    bool found = false;

	CFStringRef xcodeDevPath = copy_xcode_dev_path();

	path = CFStringCreateWithFormat(NULL, NULL, CFSTR("%s/Library/Developer/Xcode/iOS DeviceSupport/%@ (%@)"), home, version, build);
	found = path_exists(path);

	if (!found)
	{
		path = CFStringCreateWithFormat(NULL, NULL, CFSTR("%s/Library/Developer/Xcode/iOS DeviceSupport/%@"), home, version);
		found = path_exists(path);
	}
	if (!found)
	{
		path = CFStringCreateWithFormat(NULL, NULL, CFSTR("%s/Library/Developer/Xcode/iOS DeviceSupport/Latest"), home);
		found = path_exists(path);
	}
	if (!found)
	{
		path = CFStringCreateWithFormat(NULL, NULL, CFSTR("%@/Platforms/iPhoneOS.platform/DeviceSupport/%@ (%@)"), xcodeDevPath, version, build);
		found = path_exists(path);
	}
	if (!found)
	{
		path = CFStringCreateWithFormat(NULL, NULL, CFSTR("%@/Platforms/iPhoneOS.platform/DeviceSupport/%@"), xcodeDevPath, version);
		found = path_exists(path);
	}
	if (!found)
	{
		path = CFStringCreateWithFormat(NULL, NULL, CFSTR("%@/Platforms/iPhoneOS.platform/DeviceSupport/Latest"), xcodeDevPath);
		found = path_exists(path);
	}

	CFRelease(version);
	CFRelease(build);
	CFRelease(xcodeDevPath);

	if (!found)
	{
		PRINT("[ !! ] Unable to locate DeviceSupport directory.\n");
		CFRelease(path);
		exit(EXIT_FAILURE);
	}

	return path;
}

CFStringRef copy_developer_disk_image_path(AMDeviceRef device) {
    CFStringRef version = AMDeviceCopyValue(device, 0, CFSTR("ProductVersion"));
    CFStringRef build = AMDeviceCopyValue(device, 0, CFSTR("BuildVersion"));
    const char *home = getenv("HOME");
    CFStringRef path;
    bool found = false;

	CFStringRef xcodeDevPath = copy_xcode_dev_path();

	path = CFStringCreateWithFormat(NULL, NULL, CFSTR("%s/Library/Developer/Xcode/iOS DeviceSupport/%@ (%@)/DeveloperDiskImage.dmg"), home, version, build);
	found = path_exists(path);

	if (!found)
	{
		path = CFStringCreateWithFormat(NULL, NULL, CFSTR("%s/Library/Developer/Xcode/iOS DeviceSupport/%@/DeveloperDiskImage.dmg"), home, version);
		found = path_exists(path);
	}
	if (!found)
	{
		path = CFStringCreateWithFormat(NULL, NULL, CFSTR("%s/Library/Developer/Xcode/iOS DeviceSupport/Latest/DeveloperDiskImage.dmg"), home);
		found = path_exists(path);
	}
	if (!found)
	{
		path = CFStringCreateWithFormat(NULL, NULL, CFSTR("%@/Platforms/iPhoneOS.platform/DeviceSupport/%@ (%@)/DeveloperDiskImage.dmg"), xcodeDevPath, version, build);
		found = path_exists(path);
	}
	if (!found)
	{
		path = CFStringCreateWithFormat(NULL, NULL, CFSTR("%@/Platforms/iPhoneOS.platform/DeviceSupport/%@/DeveloperDiskImage.dmg"), xcodeDevPath, version);
		found = path_exists(path);
	}
	if (!found)
	{
		path = CFStringCreateWithFormat(NULL, NULL, CFSTR("%@/Platforms/iPhoneOS.platform/DeviceSupport/Latest/DeveloperDiskImage.dmg"), xcodeDevPath);
		found = path_exists(path);
	}
	
	if (!found && CFStringGetLength (version) == 5) {
		CFStringRef ver = CFStringCreateWithSubstring (NULL, version, CFRangeMake (0, 3));
		path = CFStringCreateWithFormat(NULL, NULL, CFSTR("%@/Platforms/iPhoneOS.platform/DeviceSupport/%@/DeveloperDiskImage.dmg"), xcodeDevPath, ver);
		found = path_exists(path);
		CFRelease (ver);
	}

	CFRelease(version);
	CFRelease(build);
	CFRelease(xcodeDevPath);

    if (!found)
	{
		PRINT("[ !! ] Unable to locate DeviceSupport directory containing DeveloperDiskImage.dmg.\n");

		CFIndex pathLength = CFStringGetLength(path);
		char *buffer = calloc(pathLength + 1, sizeof(char));
		Boolean success = CFStringGetCString(path, buffer, pathLength + 1, kCFStringEncodingUTF8);
		CFRelease(path);

		if (success) PRINT("[ !! ] Last path checked: %s\n", buffer);
		exit(EXIT_FAILURE);
	}

	return path;
}

void mount_callback(CFDictionaryRef dict, int arg) {
    CFStringRef status = CFDictionaryGetValue(dict, CFSTR("Status"));

    if (CFEqual(status, CFSTR("LookingUpImage"))) {
        PRINT("[  0%%] Looking up developer disk image\n");
    } else if (CFEqual(status, CFSTR("CopyingImage"))) {
        PRINT("[ 30%%] Copying DeveloperDiskImage.dmg to device\n");
    } else if (CFEqual(status, CFSTR("MountingImage"))) {
        PRINT("[ 90%%] Mounting developer disk image\n");
    }
}

void mount_developer_image(AMDeviceRef device) {
    CFStringRef ds_path = copy_device_support_path(device);
    CFStringRef image_path = copy_developer_disk_image_path(device);
    CFStringRef sig_path = CFStringCreateWithFormat(NULL, NULL, CFSTR("%@.signature"), image_path);
    CFRelease(ds_path);

    if (verbose) {
        PRINT("Device support path: ");
        fflush(stdout);
        CFShow(ds_path);
        PRINT("Developer disk image: ");
        fflush(stdout);
        CFShow(image_path);
    }

    FILE* sig = fopen(CFStringGetCStringPtr(sig_path, kCFStringEncodingMacRoman), "rb");
    void *sig_buf = malloc(128);
    assert(fread(sig_buf, 1, 128, sig) == 128);
    fclose(sig);
    CFDataRef sig_data = CFDataCreateWithBytesNoCopy(NULL, sig_buf, 128, NULL);
    CFRelease(sig_path);

    CFTypeRef keys[] = { CFSTR("ImageSignature"), CFSTR("ImageType") };
    CFTypeRef values[] = { sig_data, CFSTR("Developer") };
    CFDictionaryRef options = CFDictionaryCreate(NULL, (const void **)&keys, (const void **)&values, 2, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFRelease(sig_data);

    int result = AMDeviceMountImage(device, image_path, options, &mount_callback, 0);
    if (result == 0) {
        PRINT("[ 95%%] Developer disk image mounted successfully\n");
    } else if (result == 0xe8000076 /* already mounted */) {
        PRINT("[ 95%%] Developer disk image already mounted\n");
    } else {
        PRINT("[ !! ] Unable to mount developer disk image. (%x)\n", result);
        exit(EXIT_FAILURE);
    }

    CFRelease(image_path);
    CFRelease(options);
}

void transfer_callback(CFDictionaryRef dict, int arg) {
    int percent;
    CFStringRef status = CFDictionaryGetValue(dict, CFSTR("Status"));
    CFNumberGetValue(CFDictionaryGetValue(dict, CFSTR("PercentComplete")), kCFNumberSInt32Type, &percent);

    if (CFEqual(status, CFSTR("CopyingFile"))) {
        CFStringRef path = CFDictionaryGetValue(dict, CFSTR("Path"));

        if ((last_path == NULL || !CFEqual(path, last_path)) && !CFStringHasSuffix(path, CFSTR(".ipa"))) {
            PRINT("[%3d%%] Copying %s to device\n", percent / 2, CFStringGetCStringPtr(path, kCFStringEncodingMacRoman));
        }

        if (last_path != NULL) {
            CFRelease(last_path);
        }
        last_path = CFStringCreateCopy(NULL, path);
    }
}

void operation_callback(CFDictionaryRef dict, int arg) {
    int percent;
    CFStringRef status = CFDictionaryGetValue(dict, CFSTR("Status"));
    CFNumberGetValue(CFDictionaryGetValue(dict, CFSTR("PercentComplete")), kCFNumberSInt32Type, &percent);

    PRINT("[%3d%%] %s\n", (percent / 2) + 50, CFStringGetCStringPtr(status, kCFStringEncodingMacRoman));
}

CFURLRef copy_device_app_url(AMDeviceRef device, CFStringRef identifier) {
    CFDictionaryRef result;
    assert(AMDeviceLookupApplications(device, 0, &result) == 0);

    CFDictionaryRef app_dict = CFDictionaryGetValue(result, identifier);
    assert(app_dict != NULL);

    CFStringRef app_path = CFDictionaryGetValue(app_dict, CFSTR("Path"));
    assert(app_path != NULL);

//	printf ("AAA: %s\n", CFStringGetCStringPtr(app_path, CFStringGetSystemEncoding()));

    CFURLRef url = CFURLCreateWithFileSystemPath(NULL, app_path, kCFURLPOSIXPathStyle, true);
    CFRelease(result);
    return url;
}

CFStringRef copy_disk_app_identifier(CFURLRef disk_app_url) {
    CFURLRef plist_url = CFURLCreateCopyAppendingPathComponent(NULL, disk_app_url, CFSTR("Info.plist"), false);
    CFReadStreamRef plist_stream = CFReadStreamCreateWithFile(NULL, plist_url);
    CFReadStreamOpen(plist_stream);
    CFPropertyListRef plist = CFPropertyListCreateWithStream(NULL, plist_stream, 0, kCFPropertyListImmutable, NULL, NULL);
    CFStringRef bundle_identifier = CFRetain(CFDictionaryGetValue(plist, CFSTR("CFBundleIdentifier")));
    CFReadStreamClose(plist_stream);

    CFRelease(plist_url);
    CFRelease(plist_stream);
    CFRelease(plist);

    return bundle_identifier;
}

void write_lldb_prep_cmds(AMDeviceRef device, CFURLRef disk_app_url) {
    CFMutableStringRef cmds = CFStringCreateMutableCopy(NULL, 0, LLDB_PREP_CMDS);
    CFRange range = { 0, CFStringGetLength(cmds) };

    CFStringRef ds_path = copy_device_support_path(device);
    CFStringFindAndReplace(cmds, CFSTR("{ds_path}"), ds_path, range, 0);
    range.length = CFStringGetLength(cmds);

    if (args) {
        CFStringRef cf_args = CFStringCreateWithCString(NULL, args, kCFStringEncodingASCII);
        CFStringFindAndReplace(cmds, CFSTR("{args}"), cf_args, range, 0);
        CFRelease(cf_args);
    } else {
        CFStringFindAndReplace(cmds, CFSTR(" {args}"), CFSTR(""), range, 0);
    }
    range.length = CFStringGetLength(cmds);

    CFStringRef bundle_identifier = copy_disk_app_identifier(disk_app_url);
    CFURLRef device_app_url = copy_device_app_url(device, bundle_identifier);
    CFStringRef device_app_path = CFURLCopyFileSystemPath(device_app_url, kCFURLPOSIXPathStyle);
    CFStringFindAndReplace(cmds, CFSTR("{device_app}"), device_app_path, range, 0);
    range.length = CFStringGetLength(cmds);

    CFStringRef disk_app_path = CFURLCopyFileSystemPath(disk_app_url, kCFURLPOSIXPathStyle);
    CFStringFindAndReplace(cmds, CFSTR("{disk_app}"), disk_app_path, range, 0);
    range.length = CFStringGetLength(cmds);

    CFURLRef device_container_url = CFURLCreateCopyDeletingLastPathComponent(NULL, device_app_url);
    CFStringRef device_container_path = CFURLCopyFileSystemPath(device_container_url, kCFURLPOSIXPathStyle);
    CFMutableStringRef dcp_noprivate = CFStringCreateMutableCopy(NULL, 0, device_container_path);
    range.length = CFStringGetLength(dcp_noprivate);
    CFStringFindAndReplace(dcp_noprivate, CFSTR("/private/var/"), CFSTR("/var/"), range, 0);
    range.length = CFStringGetLength(cmds);
    CFStringFindAndReplace(cmds, CFSTR("{device_container}"), dcp_noprivate, range, 0);
    range.length = CFStringGetLength(cmds);

    CFURLRef disk_container_url = CFURLCreateCopyDeletingLastPathComponent(NULL, disk_app_url);
    CFStringRef disk_container_path = CFURLCopyFileSystemPath(disk_container_url, kCFURLPOSIXPathStyle);
    CFStringFindAndReplace(cmds, CFSTR("{disk_container}"), disk_container_path, range, 0);

    CFDataRef cmds_data = CFStringCreateExternalRepresentation(NULL, cmds, kCFStringEncodingASCII, 0);
    FILE *out = fopen(PREP_CMDS_PATH, "w");
    fwrite(CFDataGetBytePtr(cmds_data), CFDataGetLength(cmds_data), 1, out);
    fclose(out);

    CFRelease(cmds);
    if (ds_path != NULL) CFRelease(ds_path);
    CFRelease(bundle_identifier);
    CFRelease(device_app_url);
    CFRelease(device_app_path);
    CFRelease(disk_app_path);
    CFRelease(device_container_url);
    CFRelease(device_container_path);
    CFRelease(dcp_noprivate);
    CFRelease(disk_container_url);
    CFRelease(disk_container_path);
    CFRelease(cmds_data);
}


CFSocketRef server_socket;
CFSocketRef lldb_socket;
CFWriteStreamRef serverWriteStream = NULL;
CFWriteStreamRef lldbWriteStream = NULL;

void
server_callback (CFSocketRef s, CFSocketCallBackType callbackType, CFDataRef address, const void *data, void *info)
{
	int res;

	//PRINT ("server: %s\n", CFDataGetBytePtr (data));

	if (CFDataGetLength (data) == 0) {
		// FIXME: Close the socket
		//shutdown (CFSocketGetNative (lldb_socket), SHUT_RDWR);
		//close (CFSocketGetNative (lldb_socket));
		return;
	}
	res = write (CFSocketGetNative (lldb_socket), CFDataGetBytePtr (data), CFDataGetLength (data)); 
}

void lldb_callback(CFSocketRef s, CFSocketCallBackType callbackType, CFDataRef address, const void *data, void *info)
{
	//PRINT ("lldb: %s\n", CFDataGetBytePtr (data));

	if (CFDataGetLength (data) == 0)
		return;
	write (gdbfd, CFDataGetBytePtr (data), CFDataGetLength (data));
}

void fdvendor_callback(CFSocketRef s, CFSocketCallBackType callbackType, CFDataRef address, const void *data, void *info) {
    CFSocketNativeHandle socket = (CFSocketNativeHandle)(*((CFSocketNativeHandle *)data));

	assert (callbackType == kCFSocketAcceptCallBack);
	//PRINT ("callback!\n");

    lldb_socket  = CFSocketCreateWithNative(NULL, socket, kCFSocketDataCallBack, &lldb_callback, NULL);
    CFRunLoopAddSource(CFRunLoopGetMain(), CFSocketCreateRunLoopSource(NULL, lldb_socket, 0), kCFRunLoopCommonModes);
}

void start_remote_debug_server(AMDeviceRef device) {
	char buf [256];
	int res, err, i;
	char msg [256];
	int chsum, len;
	struct stat s;
	socklen_t buflen;
	struct sockaddr name;
	int namelen;

    assert(AMDeviceStartService(device, CFSTR("com.apple.debugserver"), &gdbfd, NULL) == 0);
	assert (gdbfd);

#if 0
	//sprintf (msg, "$qC#00");
	sprintf (msg, "$QSetLogging:bitmask=LOG_ALL;#00");
	chsum = 0;
	len = strlen (msg);
	for (i = 1; i < len - 3; ++i)
		chsum += (int)msg [i];
	chsum = chsum % 256;
	sprintf (msg + len - 2, "%x", chsum);
	PRINT ("%s", msg);
	err = write (gdbfd, msg, strlen (msg));
	PRINT ("Z: %d\n", err);
	PRINT("X: %d\n", gdbfd);
	err = read (gdbfd, buf, 256);
	PRINT("Y: %d\n", err);
	if (err > 0) {
		for (i = 0; i < err; ++i)
			PRINT("%c", buf [i]);
		PRINT ("\n");
	}
	err = read (gdbfd, buf, 256);
	PRINT("Y: %d\n", err);
	if (err > 0) {
		for (i = 0; i < err; ++i)
			PRINT("%c", buf [i]);
		PRINT ("\n");
	}
#endif

	/*
	 * The debugserver connection is through a fd handle, while lldb requires a host/port to connect, so create an intermediate
	 * socket to transfer data.
	 */
	server_socket = CFSocketCreateWithNative (NULL, gdbfd, kCFSocketDataCallBack, &server_callback, NULL);
    CFRunLoopAddSource(CFRunLoopGetMain(), CFSocketCreateRunLoopSource(NULL, server_socket, 0), kCFRunLoopCommonModes);

	struct sockaddr_in addr4;
	memset(&addr4, 0, sizeof(addr4));
	addr4.sin_len = sizeof(addr4);
	addr4.sin_family = AF_INET;
	addr4.sin_port = htons(12345);
	addr4.sin_addr.s_addr = htonl(INADDR_ANY);

    CFSocketRef fdvendor = CFSocketCreate(NULL, PF_INET, 0, 0, kCFSocketAcceptCallBack, &fdvendor_callback, NULL);

    int yes = 1;
    setsockopt(CFSocketGetNative(fdvendor), SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
	int flag = 1; 
	res = setsockopt(CFSocketGetNative(fdvendor), IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
	assert (res == 0);

    CFDataRef address_data = CFDataCreate(NULL, (const UInt8 *)&addr4, sizeof(addr4));

    CFSocketSetAddress(fdvendor, address_data);
    CFRelease(address_data);
    CFRunLoopAddSource(CFRunLoopGetMain(), CFSocketCreateRunLoopSource(NULL, fdvendor, 0), kCFRunLoopCommonModes);
}

void gdb_ready_handler(int signum)
{
	_exit(EXIT_SUCCESS);
}

void handle_device(AMDeviceRef device) {
    if (found_device) return; // handle one device only

    CFStringRef found_device_id = AMDeviceCopyDeviceIdentifier(device);

    PRINT ("found device id\n");
    if (device_id != NULL) {
        if(strcmp(device_id, CFStringGetCStringPtr(found_device_id, CFStringGetSystemEncoding())) == 0) {
            found_device = true;
        } else {
            return;
        }
    } else {
        if (operation == OP_LIST_DEVICES) {
            printf ("%s\n", CFStringGetCStringPtr(found_device_id, CFStringGetSystemEncoding()));
            CFRetain(device); // don't know if this is necessary?
            return;
        }
        found_device = true;
    }

    CFRetain(device); // don't know if this is necessary?

    CFStringRef path = CFStringCreateWithCString(NULL, app_path, kCFStringEncodingASCII);
    CFURLRef relative_url = CFURLCreateWithFileSystemPath(NULL, path, kCFURLPOSIXPathStyle, false);
    CFURLRef url = CFURLCopyAbsoluteURL(relative_url);

    CFRelease(relative_url);

	if (operation == OP_INSTALL || operation == OP_UNINSTALL) {
		PRINT("[  0%%] Found device (%s), beginning install\n", CFStringGetCStringPtr(found_device_id, CFStringGetSystemEncoding()));

		AMDeviceConnect(device);
		assert(AMDeviceIsPaired(device));
		assert(AMDeviceValidatePairing(device) == 0);
		assert(AMDeviceStartSession(device) == 0);
    
    
		int afcFd;
		int startServiceAFCRetval = AMDeviceStartService(device, CFSTR("com.apple.afc"), (service_conn_t *) &afcFd, NULL);
		printf("trying to start com.apple.afc : %d\n", startServiceAFCRetval);
		
		if( startServiceAFCRetval )
		{
			sleep(1);
			//printf("trying to start com.apple.afc\n");
			startServiceAFCRetval = AMDeviceStartService(device, CFSTR("com.apple.afc"), (service_conn_t *) &afcFd, NULL);
		}
		printf("trying to start com.apple.afc : %d\n", startServiceAFCRetval);
		assert(startServiceAFCRetval == 0);
		assert(AMDeviceStopSession(device) == 0);
		assert(AMDeviceDisconnect(device) == 0);
	
		if (operation == OP_INSTALL) {
			assert(AMDeviceTransferApplication(afcFd, path, NULL, transfer_callback, NULL) == 0);
			close(afcFd);
		}
	
		CFStringRef keys[] = { CFSTR("PackageType") };
		CFStringRef values[] = { CFSTR("Developer") };
		CFDictionaryRef options = CFDictionaryCreate(NULL, (const void **)&keys, (const void **)&values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	
		AMDeviceConnect(device);
		assert(AMDeviceIsPaired(device));
		assert(AMDeviceValidatePairing(device) == 0);
		assert(AMDeviceStartSession(device) == 0);
	
		int installFd;
		assert(AMDeviceStartService(device, CFSTR("com.apple.mobile.installation_proxy"), (service_conn_t *) &installFd, NULL) == 0);
	
		assert(AMDeviceStopSession(device) == 0);
		assert(AMDeviceDisconnect(device) == 0);
	
		if (operation == OP_INSTALL) {
			mach_error_t result = AMDeviceInstallApplication(installFd, path, options, operation_callback, NULL);
			if (result != 0)
			{
				PRINT("AMDeviceInstallApplication failed: %d\n", result);
				exit(EXIT_FAILURE);
			}
		}
		else if (operation == OP_UNINSTALL) {
			mach_error_t result = AMDeviceUninstallApplication (installFd, path, NULL, operation_callback, NULL);
			if (result != 0)
			{
				PRINT("AMDeviceUninstallApplication failed: %d\n", result);
				exit(EXIT_FAILURE);
			}
		}
	
	
		close(installFd);
	
		CFRelease(path);
		CFRelease(options);
	
		if (operation == OP_INSTALL)
			PRINT("[100%%] Installed package %s\n", app_path);
		else if (operation == OP_UNINSTALL)
			PRINT("[100%%] uninstalled package %s\n", app_path);
	}


    if (!debug) exit(EXIT_SUCCESS); // no debug phase

    AMDeviceConnect(device);
    assert(AMDeviceIsPaired(device));
    assert(AMDeviceValidatePairing(device) == 0);
    assert(AMDeviceStartSession(device) == 0);

    PRINT("------ Debug phase ------\n");

    if (!no_mount)
        mount_developer_image(device);      // put debugserver on the device

    start_remote_debug_server(device);  // start debugserver
    write_lldb_prep_cmds(device, url);   // dump the necessary lldb commands into a file

    CFRelease(url);

    PRINT("[100%%] Connecting to remote debug server\n");
    PRINT("-------------------------\n");

	if (wait_with_gdb) {
		printf ("You must now execute: \n");
		printf ("%s\n", LLDB_SHELL);
		// Figure out when to exit
	} else {
		signal(SIGHUP, gdb_ready_handler);
	
		pid_t parent = getpid();
		int pid = fork();
		if (pid == 0) {
			system(LLDB_SHELL);      // launch gdb
			kill(parent, SIGHUP);  // "No. I am your father."
			_exit(EXIT_SUCCESS);
		}
    }
}

void device_callback(struct am_device_notification_callback_info *info, void *arg) {
    switch (info->msg) {
        case ADNCI_MSG_CONNECTED:
			if( info->dev->lockdown_conn ) {
				handle_device(info->dev);
			}
        default:
            break;
    }
}

void timeout_callback(CFRunLoopTimerRef timer, void *info) {
    if (!found_device) {
        PRINT("Timed out waiting for device.\n");
        exit(EXIT_FAILURE);
    }
}

void usage(const char* app) {
    printf ("usage: %s [-q/--quiet] [-t/--timeout timeout(seconds)] [-v/--verbose] <command> [<args>] \n\n", app);
    printf ("Commands available:\n");
    printf ("   install    [-i/--id device_id] -b/--bundle bundle.app [-a/--args arguments] \n");
    printf ("    * Install the specified app with optional arguments to the specified device, or all attached devices if none are specified. \n\n");
    printf ("   uninstall  [-i/--id device_id] -b/--bundle bundle.app \n");
    printf ("    * Removed the specified bundle identifier (eg com.foo.MyApp) from the specified device, or all attached devices if none are specified. \n\n");
    printf ("   debug [-w/--wait] [-n/--no-mount] [-b/--bundle bundle.app [-a/--args arguments] \n");
    printf ("    * Debug the app with the specified bundle identifier. Optional wait instead of running gdb automatically. Opt-out of mounting the developer image.\n");
    printf ("   list-devices  \n");
    printf ("    * List all attached devices. \n\n");
	printf ("   i <bundle path>\n");
	printf ("   d <bundle path>\n");
}

int main(int argc, char *argv[]) {
    static struct option global_longopts[]= {
        { "quiet", no_argument, NULL, 'q' },
        { "verbose", no_argument, NULL, 'v' },
        { "timeout", required_argument, NULL, 't' },
        
        { "id", required_argument, NULL, 'i' },
        { "bundle", required_argument, NULL, 'b' },
   
        { "debug", no_argument, NULL, 'd' },
        { "nomount", no_argument, NULL, 'n' },
        { "args", required_argument, NULL, 'a' },

        { "wait", no_argument, NULL, 'w' },
        { NULL, 0, NULL, 0 },
    };

    char ch;
    while ((ch = getopt_long(argc, argv, "qvtibdan:", global_longopts, NULL)) != -1)
    {
        switch (ch) {
        case 'q':
            quiet = 1;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'd':
            debug = 1;
            break;
        case 't':
            timeout = atoi(optarg);
            break;
        case 'b':
            app_path = optarg;
            break;
        case 'a':
            args = optarg;
            break;
        case 'i':
            device_id = optarg;
            break;
        case 'w':
            wait_with_gdb = 1;
            break;
        case 'n':
            no_mount = 1;
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    operation = OP_NONE;
	if (debug) {
		operation = OP_DEBUG;
	} else if (strcmp (argv [optind], "install") == 0) {
        operation = OP_INSTALL;
    } else if (strcmp (argv [optind], "uninstall") == 0) {
        operation = OP_UNINSTALL;
    } else if (strcmp (argv [optind], "list-devices") == 0) {
        operation = OP_LIST_DEVICES;
    } else if (strcmp (argv [optind], "debug") == 0) {
        operation = OP_DEBUG;
        debug = 1;
	} else if (strcmp (argv [optind], "i") == 0) {
        operation = OP_INSTALL;
        app_path = argv [optind + 1];
	} else if (strcmp (argv [optind], "d") == 0) {
        operation = OP_DEBUG;
        debug = 1;
        app_path = argv [optind + 1];
    } else {
        usage (argv [0]);
        exit(EXIT_SUCCESS);
    }

    if (operation != OP_LIST_DEVICES && !app_path) {
        usage(argv[0]);
        exit(EXIT_SUCCESS);
    }

    if (operation == OP_INSTALL)
        assert(access(app_path, F_OK) == 0);

    AMDSetLogLevel(1+4+2+8+16+32+64+128); // otherwise syslog gets flooded with crap
    if (timeout > 0)
    {
        CFRunLoopTimerRef timer = CFRunLoopTimerCreate(NULL, CFAbsoluteTimeGetCurrent() + timeout, 0, 0, 0, timeout_callback, NULL);
        CFRunLoopAddTimer(CFRunLoopGetCurrent(), timer, kCFRunLoopCommonModes);
        PRINT("[....] Waiting up to %d seconds for iOS device to be connected\n", timeout);
    }
    else
    {
        PRINT("[....] Waiting for iOS device to be connected\n");
    }

    struct am_device_notification *notify;
    AMDeviceNotificationSubscribe(&device_callback, 0, 0, NULL, &notify);
	
    CFRunLoopRun();
}
