"""Build small independent artifacts for real SRD installer verification."""
import json,plistlib,subprocess,zipfile
from pathlib import Path
from repair_device_connection import HERE

def build():
    output=HERE/'installer-verification';output.mkdir(exist_ok=True)
    package=output/'deb-root';(package/'DEBIAN').mkdir(parents=True,exist_ok=True)
    (package/'DEBIAN/control').write_text('Package: com.liquidsky.install-check\nVersion: 1.0\nArchitecture: all\nMaintainer: 0-Sky Project\nDescription: Temporary installer verification fixture\n')
    marker=package/'var/jb/usr/share/0-sky-install-check/marker.txt';marker.parent.mkdir(parents=True,exist_ok=True);marker.write_text('DEB installation verified\n')
    deb=output/'0-sky-install-check.deb'
    subprocess.run(['/opt/homebrew/bin/dpkg-deb','--build','--root-owner-group',str(package),str(deb)],check=True,capture_output=True)
    app=output/'Payload/InstallCheck.app';app.mkdir(parents=True,exist_ok=True)
    source=output/'main.m'
    source.write_text('''#import <UIKit/UIKit.h>
@interface Delegate : UIResponder <UIApplicationDelegate>
@property(strong,nonatomic) UIWindow *window;
@end
@implementation Delegate
- (BOOL)application:(UIApplication *)a didFinishLaunchingWithOptions:(NSDictionary *)o {
 self.window=[[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
 UIViewController *c=[UIViewController new];c.view.backgroundColor=UIColor.systemBackgroundColor;
 UILabel *l=[[UILabel alloc] initWithFrame:CGRectMake(20,100,350,80)];l.text=@"0-Sky installer verified";[c.view addSubview:l];
 self.window.rootViewController=c;[self.window makeKeyAndVisible];return YES;
}
@end
int main(int argc,char **argv){@autoreleasepool{return UIApplicationMain(argc,argv,nil,NSStringFromClass(Delegate.class));}}
''')
    sdk=subprocess.check_output(['/usr/bin/xcrun','--sdk','iphoneos','--show-sdk-path'],text=True).strip()
    subprocess.run(['/usr/bin/xcrun','--sdk','iphoneos','clang','-target','arm64-apple-ios17.0','-isysroot',sdk,'-fobjc-arc','-framework','UIKit','-framework','Foundation',str(source),'-o',str(app/'InstallCheck')],check=True,capture_output=True)
    (app/'Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':'com.liquidsky.InstallCheck','CFBundleExecutable':'InstallCheck','CFBundleName':'InstallCheck','CFBundleDisplayName':'0-Sky Install Check','CFBundlePackageType':'APPL','CFBundleVersion':'1','CFBundleShortVersionString':'1.0','MinimumOSVersion':'17.0','LSRequiresIPhoneOS':True,'UIDeviceFamily':[1,2],'UILaunchScreen':{}}))
    subprocess.run(['/usr/bin/codesign','--force','--sign','-',str(app)],check=True,capture_output=True)
    ipa=output/'0-sky-install-check.ipa'
    with zipfile.ZipFile(ipa,'w',zipfile.ZIP_DEFLATED) as archive:
        for path in app.rglob('*'):
            if path.is_file():archive.write(path,path.relative_to(output).as_posix())
    return {'deb':str(deb),'ipa':str(ipa)}

if __name__=='__main__':print(json.dumps(build(),indent=2))
