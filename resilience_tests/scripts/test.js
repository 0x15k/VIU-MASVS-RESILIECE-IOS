
function app_env_info(DEBUG)
{
	console.log("")
	console.warn("-----------------------------------")
	console.warn("|     Application Environment     |")
	console.warn("-----------------------------------")
	var mainBundlePath = String(ObjC.classes.NSBundle.mainBundle())
	mainBundlePath = mainBundlePath.substring(0, mainBundlePath.indexOf(">"))
	mainBundlePath = mainBundlePath.substring(mainBundlePath.indexOf("<")+1)
	console.log("App Bundle Path    : " + mainBundlePath)
	//Credit: https://github.com/iddoeldor/frida-snippets#find-ios-application-uuid
	var mainBundleContainerPathIdentifier = "";
	var bundleIdentifier = String(ObjC.classes.NSBundle.mainBundle().objectForInfoDictionaryKey_('CFBundleIdentifier'));
	var path_prefix = "/var/mobile/Containers/Data/Application/";
	var plist_metadata = "/.com.apple.mobile_container_manager.metadata.plist";
	var folders = ObjC.classes.NSFileManager.defaultManager().contentsOfDirectoryAtPath_error_(path_prefix, NULL);
	for(var i = 0, l = folders.count(); i < l; i++)
	{
		var uuid = folders.objectAtIndex_(i);
		var metadata = path_prefix + uuid + plist_metadata;
		var dict = ObjC.classes.NSMutableDictionary.alloc().initWithContentsOfFile_(metadata);
		var enumerator = dict.keyEnumerator();
		var key;
		while ((key = enumerator.nextObject()) !== null)
		{
			if(key == 'MCMMetadataIdentifier')
			{
				var appId = String(dict.objectForKey_(key));
				if(appId.indexOf(bundleIdentifier) != -1)
				{
					mainBundleContainerPathIdentifier = uuid;
					break;
				}
			}
		}
	}
	console.log("App Container Path : /var/mobile/Containers/Data/Application/" + mainBundleContainerPathIdentifier + "/")
}

setImmediate(app_env_info)