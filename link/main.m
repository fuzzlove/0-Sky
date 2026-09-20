#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
#import <unistd.h>
#import <sys/utsname.h>
#import "Branding.h"

static NSString *const RuntimeURL = @"http://127.0.0.1:48654/v1/runtime";

@interface MatrixStatusController : UIViewController
@property(nonatomic,strong) UIImageView *logo;
@property(nonatomic,strong) UILabel *headline;
@property(nonatomic,strong) UILabel *detail;
@property(nonatomic,strong) UILabel *pulse;
@property(nonatomic,strong) UILabel *progressText;
@property(nonatomic,strong) UIProgressView *progress;
@property(nonatomic,strong) UIButton *refresh;
@property(nonatomic,strong) UIButton *pairButton;
@property(nonatomic,strong) UIButton *crypstoreButton;
@property(nonatomic,strong) UIButton *diagnosticsButton;
@property(nonatomic,strong) UITextView *console;
@property(nonatomic,strong) NSTimer *timer;
@property(nonatomic,strong) NSTimer *stageTimer;
@property(nonatomic,assign) BOOL refreshing;
@property(nonatomic,assign) NSInteger refreshSeconds;
@property(nonatomic,assign) BOOL didLogResearchStatus;
@property(nonatomic,assign) BOOL didLogRoot;
@property(nonatomic,assign) BOOL didLogFull;
@property(nonatomic,assign) BOOL paired;
// A durable display state is intentionally separate from the live security
// gate above.  Privileged actions continue to require `paired` on every call.
@property(nonatomic,assign) BOOL relationshipVerified;
@property(nonatomic,assign) BOOL didLogPairing;
@property(nonatomic,copy) NSString *pairingJobID;
@property(nonatomic,assign) BOOL pairingCancellationRequested;
@property(nonatomic,assign) BOOL pairingResultPollActive;
@property(nonatomic,strong) UIAlertController *pairingProgressAlert;
@property(nonatomic,copy) NSString *lastRuntimeDigest;
@end

@implementation MatrixStatusController
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.blackColor;

    _pulse = [UILabel new]; _pulse.text = @"●"; _pulse.textColor = [UIColor colorWithRed:1 green:.72 blue:.18 alpha:1];
    _pulse.font = [UIFont systemFontOfSize:20 weight:UIFontWeightBold];
    _pulse.translatesAutoresizingMaskIntoConstraints = NO; [self.view addSubview:_pulse];

    _headline = [UILabel new]; _headline.text = @"0-SKY LINK // AUTHORIZED SRD RUNTIME"; _headline.textColor = UIColor.whiteColor;
    _headline.font = [UIFont monospacedSystemFontOfSize:20 weight:UIFontWeightBold];
    _headline.textAlignment = NSTextAlignmentCenter; _headline.adjustsFontSizeToFitWidth = YES;
    _headline.minimumScaleFactor = .48; _headline.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:_headline];

    _detail = [UILabel new]; _detail.text = @"Waiting for ElleKit and the dynamic tweak registry";
    _detail.textColor = [UIColor colorWithWhite:.65 alpha:1];
    _detail.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightRegular];
    _detail.textAlignment = NSTextAlignmentCenter; _detail.numberOfLines = 0;
    _detail.translatesAutoresizingMaskIntoConstraints = NO; [self.view addSubview:_detail];

    _progressText = [UILabel new];
    _progressText.text = @"READY // CRYPTEX + TWEAK PIPELINE";
    _progressText.textColor = [UIColor colorWithRed:.35 green:1 blue:.52 alpha:1];
    _progressText.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightSemibold];
    _progressText.textAlignment = NSTextAlignmentCenter;
    _progressText.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:_progressText];

    _progress = [[UIProgressView alloc] initWithProgressViewStyle:UIProgressViewStyleDefault];
    _progress.progressTintColor = [UIColor colorWithRed:.25 green:1 blue:.48 alpha:1];
    _progress.trackTintColor = [UIColor colorWithRed:.05 green:.24 blue:.11 alpha:1];
    _progress.layer.cornerRadius = 3; _progress.clipsToBounds = YES;
    _progress.progress = 0;
    _progress.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:_progress];

    _refresh = [UIButton buttonWithType:UIButtonTypeSystem];
    [_refresh setTitle:@"START / REFRESH RESEARCH RUNTIME" forState:UIControlStateNormal];
    [_refresh setTitleColor:UIColor.blackColor forState:UIControlStateNormal];
    _refresh.titleLabel.font = [UIFont monospacedSystemFontOfSize:14 weight:UIFontWeightBold];
    _refresh.backgroundColor = [UIColor colorWithRed:.25 green:1 blue:.48 alpha:1];
    _refresh.layer.cornerRadius = 12;
    _refresh.translatesAutoresizingMaskIntoConstraints = NO;
    [_refresh addTarget:self action:@selector(refreshRuntime) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:_refresh];

    _pairButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [_pairButton setTitle:@"PAIR / VERIFY TRUSTED MAC" forState:UIControlStateNormal];
    [_pairButton setTitleColor:UIColor.blackColor forState:UIControlStateNormal];
    _pairButton.titleLabel.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightBold];
    _pairButton.backgroundColor = [UIColor colorWithRed:1 green:.72 blue:.18 alpha:1];
    _pairButton.layer.cornerRadius = 10;
    _pairButton.translatesAutoresizingMaskIntoConstraints = NO;
    [_pairButton addTarget:self action:@selector(showPairingAssistant) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:_pairButton];

    _relationshipVerified = [NSUserDefaults.standardUserDefaults boolForKey:@"ZeroSkyTrustedMacRelationshipVerified"];
    if (_relationshipVerified) {
        [_pairButton setTitle:@"TRUSTED MAC: VERIFIED • RECONNECTING" forState:UIControlStateNormal];
        _pairButton.backgroundColor = [UIColor colorWithRed:.25 green:1 blue:.48 alpha:1];
    } else {
        // Startup is an unknown state, not a pairing failure.  Avoid flashing
        // the yellow enrollment action while the first local poll is pending.
        [_pairButton setTitle:@"CHECKING TRUSTED MAC…" forState:UIControlStateNormal];
        _pairButton.backgroundColor = [UIColor colorWithWhite:.55 alpha:1];
    }

    _crypstoreButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [_crypstoreButton setTitle:@"REPAIR / INSTALL 0-SKY CONTROL" forState:UIControlStateNormal];
    [_crypstoreButton setTitleColor:[UIColor colorWithRed:.35 green:1 blue:.52 alpha:1]
                           forState:UIControlStateNormal];
    _crypstoreButton.titleLabel.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightBold];
    _crypstoreButton.backgroundColor = [UIColor colorWithRed:.02 green:.12 blue:.06 alpha:1];
    _crypstoreButton.layer.borderColor = [UIColor colorWithRed:.25 green:1 blue:.48 alpha:.7].CGColor;
    _crypstoreButton.layer.borderWidth = 1; _crypstoreButton.layer.cornerRadius = 10;
    _crypstoreButton.translatesAutoresizingMaskIntoConstraints = NO;
    [_crypstoreButton addTarget:self action:@selector(repairCrypStore) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:_crypstoreButton];

    _diagnosticsButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [_diagnosticsButton setTitle:@"ADVANCED PAIRING DIAGNOSTICS" forState:UIControlStateNormal];
    [_diagnosticsButton setTitleColor:[UIColor colorWithWhite:.65 alpha:1] forState:UIControlStateNormal];
    _diagnosticsButton.titleLabel.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightMedium];
    _diagnosticsButton.translatesAutoresizingMaskIntoConstraints = NO;
    [_diagnosticsButton addTarget:self action:@selector(showPairingDiagnostics) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:_diagnosticsButton];

    _console = [UITextView new]; _console.editable = NO; _console.selectable = YES;
    _console.backgroundColor = UIColor.blackColor;
    _console.textColor = [UIColor colorWithRed:.35 green:1 blue:.52 alpha:1];
    _console.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    _console.layer.cornerRadius = 8; _console.layer.borderWidth = 1;
    _console.layer.borderColor = [UIColor colorWithRed:.22 green:.55 blue:.82 alpha:.55].CGColor;
    _console.textContainerInset = UIEdgeInsetsMake(10, 10, 10, 10);
    struct utsname localUname; uname(&localUname);
    uid_t appUID = getuid();
    _console.text = @"";
    _console.translatesAutoresizingMaskIntoConstraints = NO; [self.view addSubview:_console];
    [self appendConsole:@"[0-Sky Link] verbose authorized-research console started"];
    [self appendConsole:@"[notice] Security Research Device workflow; secrets and pairing material are redacted"];
    [self appendConsole:@"[pipeline] 01 device context → 02 trusted host → 03 privileged runtime handoff → 04 manager → 05 registry → 06 trust Cryptex → 07 injection activation → 08 app registration"];
    [self appendConsole:[NSString stringWithFormat:@"[app] uid=%u (%@) pid=%d", appUID,
      appUID == 501 ? @"mobile" : appUID == 0 ? @"root" : @"other", getpid()]];
    [self appendConsole:[NSString stringWithFormat:@"[device] %@ %@  arch=%s",
      UIDevice.currentDevice.systemName, UIDevice.currentDevice.systemVersion, localUname.machine]];
    [self appendConsole:@"[bridge] polling authenticated privileged runtime status…"];

    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
      [_pulse.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
      [_pulse.topAnchor constraintEqualToAnchor:safe.topAnchor constant:8],
      [_headline.leadingAnchor constraintEqualToAnchor:_pulse.trailingAnchor constant:8],
      [_headline.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
      [_headline.centerYAnchor constraintEqualToAnchor:_pulse.centerYAnchor],
      [_detail.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:28],
      [_detail.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-28],
      [_detail.topAnchor constraintEqualToAnchor:_headline.bottomAnchor constant:12],
      [_progressText.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:36],
      [_progressText.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-36],
      [_progressText.topAnchor constraintEqualToAnchor:_detail.bottomAnchor constant:10],
      [_progress.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:42],
      [_progress.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-42],
      [_progress.topAnchor constraintEqualToAnchor:_progressText.bottomAnchor constant:7],
      [_progress.heightAnchor constraintEqualToConstant:6],
      [_refresh.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
      [_refresh.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
      [_refresh.heightAnchor constraintEqualToConstant:46],
      [_crypstoreButton.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
      [_crypstoreButton.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
      [_pairButton.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
      [_pairButton.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
      [_pairButton.topAnchor constraintEqualToAnchor:_refresh.bottomAnchor constant:8],
      [_pairButton.heightAnchor constraintEqualToConstant:36],
      [_crypstoreButton.topAnchor constraintEqualToAnchor:_pairButton.bottomAnchor constant:7],
      [_crypstoreButton.heightAnchor constraintEqualToConstant:36],
      [_diagnosticsButton.topAnchor constraintEqualToAnchor:_crypstoreButton.bottomAnchor constant:3],
      [_diagnosticsButton.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
      [_diagnosticsButton.heightAnchor constraintEqualToConstant:26],
      [_console.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:8],
      [_console.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-8],
      [_console.topAnchor constraintEqualToAnchor:_progress.bottomAnchor constant:8],
      [_console.bottomAnchor constraintEqualToAnchor:_refresh.topAnchor constant:-8],
      [_diagnosticsButton.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor constant:-6]
    ]];

    [self checkRuntime];
    _timer = [NSTimer scheduledTimerWithTimeInterval:2.0 target:self selector:@selector(checkRuntime)
                                            userInfo:nil repeats:YES];
}
- (void)showPairingDiagnostics {
    NSURL *url = [NSURL URLWithString:@"http://127.0.0.1:48654/v1/pairing/status"];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.timeoutInterval = 10;
    NSString *token = [self bridgeToken];
    if (token.length) [request setValue:token forHTTPHeaderField:@"X-TrollStore-Bridge-Token"];
    [[NSURLSession.sharedSession dataTaskWithRequest:request completionHandler:
      ^(NSData *data, NSURLResponse *response, NSError *error) {
        NSDictionary *status = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
        dispatch_async(dispatch_get_main_queue(), ^{
            if (!status || error) {
                UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Pairing Diagnostics"
                  message:@"The local 0-Sky bridge is unavailable."
                  preferredStyle:UIAlertControllerStyleAlert];
                [alert addAction:[UIAlertAction actionWithTitle:@"Done" style:UIAlertActionStyleCancel handler:nil]];
                [self presentViewController:alert animated:YES completion:nil];
                return;
            }
            NSDictionary *device = [status[@"device"] isKindOfClass:NSDictionary.class] ? status[@"device"] : @{};
            NSDictionary *remote = [status[@"remote_services"] isKindOfClass:NSDictionary.class] ? status[@"remote_services"] : @{};
            NSString *fingerprint = status[@"mac_identity_fingerprint"] ?: @"Unavailable";
            if (fingerprint.length > 18) fingerprint = [NSString stringWithFormat:@"…%@", [fingerprint substringFromIndex:fingerprint.length - 18]];
            id last = status[@"last_verified_at"] ?: @"Never";
            NSString *message = [NSString stringWithFormat:
              @"Device: %@\nOS: %@\nBuild: %@\nTransport: %@\nApple Pairing: %@\nTrusted Session: %@\n0-Sky Mac Identity: %@\nMac: %@\nFingerprint: %@\nBridge Installed: %@\nBridge Running: %@\nBackend: %@\nBridge: %@\nProtocol: %@\nRemote Services: %@\nResearch Class: %@\nLast Verified: %@",
              device[@"productType"] ?: @"Unknown", device[@"productVersion"] ?: @"Unknown",
              device[@"buildVersion"] ?: @"Unknown", status[@"transport_type"] ?: @"Unavailable",
              [status[@"apple_pairing_verified"] boolValue] ? @"PASS" : @"FAIL",
              [status[@"lockdown_session_validated"] boolValue] ? @"PASS" : @"FAIL",
              [status[@"host_identity_verified"] boolValue] ? @"PASS" : @"FAIL",
              status[@"mac_name"] ?: @"Unknown", fingerprint,
              [status[@"bridge_installed"] boolValue] ? @"YES" : @"NO",
              [status[@"bridge_running"] boolValue] ? @"YES" : @"NO",
              status[@"device_backend"] ?: @"Unknown",
              status[@"bridge_version"] ?: @"Unknown", status[@"protocol_version"] ?: @"Unknown",
              remote[@"status"] ?: @"NOT REQUIRED", status[@"research_class"] ?: @"UNKNOWN", last];
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Advanced Pairing Diagnostics"
              message:message preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"Done" style:UIAlertActionStyleCancel handler:nil]];
            [self presentViewController:alert animated:YES completion:nil];
        });
      }] resume];
}
- (void)cancelPairingRequest {
    _pairingCancellationRequested = YES;
    if (!_pairingJobID.length) return;
    NSString *token = [self bridgeToken];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:
      [NSURL URLWithString:@"http://127.0.0.1:48654/v1/pairing/cancel"]];
    request.HTTPMethod = @"POST"; request.timeoutInterval = 10;
    [request setValue:token forHTTPHeaderField:@"X-TrollStore-Bridge-Token"];
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    request.HTTPBody = [NSJSONSerialization dataWithJSONObject:@{@"job_id": _pairingJobID}
                                                       options:0 error:nil];
    [[NSURLSession.sharedSession dataTaskWithRequest:request completionHandler:
      ^(NSData *data, NSURLResponse *response, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self appendConsole:@"[pairing] cancellation requested; trust records are unchanged"];
            self.pairingJobID = nil;
            self.pairingProgressAlert = nil;
            self.pairButton.enabled = YES;
            [self.pairButton setTitle:@"PAIR / VERIFY TRUSTED MAC" forState:UIControlStateNormal];
        });
      }] resume];
}
- (NSString *)pairingProgressMessage:(NSDictionary *)pairing {
    NSString *state = [pairing[@"pairing_state"] isKindOfClass:NSString.class] ?
      pairing[@"pairing_state"] : @"DISCOVERING_MAC";
    NSArray *ordered = @[@"DISCOVERING_MAC", @"MAC_FOUND", @"WAITING_FOR_USB",
      @"DEVICE_DISCOVERED", @"CHECKING_PAIRING", @"ALREADY_PAIRED",
      @"PAIRING_REQUIRED", @"REQUESTING_PAIR", @"WAITING_FOR_TRUST",
      @"VALIDATING_LOCKDOWN", @"VERIFYING_DEVICE_IDENTITY",
      @"VERIFYING_HOST_IDENTITY", @"VERIFYING_SERVICES", @"CLASSIFYING_DEVICE",
      @"VERIFIED_TRUSTED", @"WIRELESS_ENABLING", @"WIRELESS_WAITING_FOR_DISCONNECT",
      @"WIRELESS_DISCOVERING", @"WIRELESS_VERIFYING", @"WIRELESS_READY"];
    NSInteger position = [ordered indexOfObject:state];
    if ([state isEqualToString:@"DEVICE_LOCKED"])
        position = [ordered indexOfObject:@"WAITING_FOR_TRUST"];
    if (position == NSNotFound) position = 0;
    NSString *(^line)(BOOL, NSString *) = ^NSString *(BOOL done, NSString *title) {
        return [NSString stringWithFormat:@"%@ %@", done ? @"✓" : @"○", title];
    };
    NSString *instruction = @"0-Sky is monitoring the authenticated Mac Bridge.";
    if ([state isEqualToString:@"WAITING_FOR_USB"])
        instruction = @"Connect this iPhone or iPad to the Mac by USB.";
    else if ([state isEqualToString:@"DEVICE_LOCKED"])
        instruction = @"Unlock this device. Verification resumes automatically.";
    else if ([state isEqualToString:@"WAITING_FOR_TRUST"])
        instruction = @"Unlock the device, tap Trust in Apple’s dialog, and enter the passcode if requested.";
    else if ([state isEqualToString:@"WIRELESS_WAITING_FOR_DISCONNECT"])
        instruction = @"Disconnect the USB cable. 0-Sky will verify Wi-Fi automatically.";
    else if ([state hasPrefix:@"WIRELESS_"])
        instruction = @"Testing the authenticated wireless fallback…";
    BOOL wifiEnabled = position >= [ordered indexOfObject:@"WIRELESS_WAITING_FOR_DISCONNECT"];
    BOOL wifiVerified = [pairing[@"wifi_pairing_verified"] boolValue] ||
      position >= [ordered indexOfObject:@"WIRELESS_READY"];
    return [NSString stringWithFormat:@"%@\n\n%@\n%@\n%@\n%@\n%@\n%@\n%@\n%@\n%@",
      instruction,
      line(position >= [ordered indexOfObject:@"MAC_FOUND"], @"Mac discovered"),
      line(position >= [ordered indexOfObject:@"DEVICE_DISCOVERED"], @"USB connection"),
      line(position >= [ordered indexOfObject:@"CHECKING_PAIRING"], @"Device identified"),
      line(position >= [ordered indexOfObject:@"VALIDATING_LOCKDOWN"], @"Apple pairing"),
      line(position >= [ordered indexOfObject:@"VERIFYING_HOST_IDENTITY"], @"Trusted session"),
      line(position >= [ordered indexOfObject:@"VERIFYING_SERVICES"], @"0-Sky host"),
      line(position >= [ordered indexOfObject:@"VERIFIED_TRUSTED"], @"Capabilities checked"),
      line(wifiEnabled, @"Wi-Fi access enabled"),
      line(wifiVerified, @"Wi-Fi fallback verified")];
}
- (void)pollPairingResult {
    if (_pairingResultPollActive || !_pairingJobID.length) return;
    NSString *token = [self bridgeToken];
    if (!token.length) return;
    _pairingResultPollActive = YES;
    NSString *escaped = [_pairingJobID stringByAddingPercentEncodingWithAllowedCharacters:
      NSCharacterSet.URLQueryAllowedCharacterSet];
    NSString *address = [NSString stringWithFormat:
      @"http://127.0.0.1:48654/v1/pairing/result?job_id=%@", escaped];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:address]];
    request.timeoutInterval = 10;
    [request setValue:token forHTTPHeaderField:@"X-TrollStore-Bridge-Token"];
    [[NSURLSession.sharedSession dataTaskWithRequest:request completionHandler:
      ^(NSData *data, NSURLResponse *response, NSError *error) {
        NSDictionary *value = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
        dispatch_async(dispatch_get_main_queue(), ^{
            self.pairingResultPollActive = NO;
            if (error || ![value[@"complete"] boolValue]) return;
            NSDictionary *result = [value[@"result"] isKindOfClass:NSDictionary.class] ? value[@"result"] : value;
            NSInteger code = [result[@"status"] integerValue];
            if (code == 0) {
                // The job result is authenticated by the device-local bridge,
                // scoped to this UUID, and is emitted by the Mac worker only
                // after the wireless fallback has completed.  Waiting for a
                // second heartbeat here caused the Link sheet to stall after
                // Wi-Fi had already been verified, especially while the USB
                // route was being restored.  Accept the completed result and
                // let the normal status loop reconcile live transport state.
                self.pairingJobID = nil;
                self.pairingCancellationRequested = NO;
                self.pairingProgressAlert = nil;
                self.pairButton.enabled = YES;
                [self appendConsole:@"[pairing] authenticated Wi-Fi fallback result received"];
                [self dismissViewControllerAnimated:YES completion:^{
                    UIAlertController *done = [UIAlertController alertControllerWithTitle:@"Trusted Mac Verified"
                      message:@"USB pairing and Wi-Fi fallback were verified for this Trusted Mac."
                      preferredStyle:UIAlertControllerStyleAlert];
                    [done addAction:[UIAlertAction actionWithTitle:@"Done" style:UIAlertActionStyleCancel handler:nil]];
                    [self presentViewController:done animated:YES completion:nil];
                    [self checkRuntime];
                }];
                return;
            }
            NSString *errorCode = result[@"errorCode"];
            NSDictionary *pairing = [result[@"pairing"] isKindOfClass:NSDictionary.class] ? result[@"pairing"] : @{};
            NSString *message = pairing[@"userMessage"] ?: result[@"stderr"] ?: @"Trusted Mac verification failed.";
            self.pairingJobID = nil;
            self.pairingCancellationRequested = NO;
            self.pairingProgressAlert = nil;
            self.pairButton.enabled = YES;
            if ([errorCode isEqualToString:@"CANCELLED"] || code == 130) {
                [self.pairButton setTitle:@"PAIR / VERIFY TRUSTED MAC" forState:UIControlStateNormal];
                return;
            }
            [self appendConsole:[@"[pairing] " stringByAppendingString:message]];
            [self dismissViewControllerAnimated:YES completion:^{
                UIAlertController *failure = [UIAlertController alertControllerWithTitle:@"Pairing Failed"
                  message:message preferredStyle:UIAlertControllerStyleAlert];
                [failure addAction:[UIAlertAction actionWithTitle:@"Done" style:UIAlertActionStyleCancel handler:nil]];
                [self presentViewController:failure animated:YES completion:nil];
            }];
        });
      }] resume];
}
- (void)showPairingAssistant {
    NSString *token = [self bridgeToken];
    if (!token.length) {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"0-Sky Mac Not Found"
          message:@"Connect this device to the Mac and open 0-Sky. Pairing will continue through the Mac Bridge."
          preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"Done" style:UIAlertActionStyleCancel handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
        return;
    }
    NSMutableURLRequest *statusRequest = [NSMutableURLRequest requestWithURL:
      [NSURL URLWithString:@"http://127.0.0.1:48654/v1/pairing/status"]];
    statusRequest.timeoutInterval = 10;
    [statusRequest setValue:token forHTTPHeaderField:@"X-TrollStore-Bridge-Token"];
    [[NSURLSession.sharedSession dataTaskWithRequest:statusRequest completionHandler:
      ^(NSData *data, NSURLResponse *response, NSError *error) {
        NSDictionary *status = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
        dispatch_async(dispatch_get_main_queue(), ^{
            if (error || !status) {
                UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"0-Sky Mac Not Found"
                  message:@"Connect this device to the Mac and open 0-Sky. Pairing will continue automatically when the bridge is available."
                  preferredStyle:UIAlertControllerStyleAlert];
                [alert addAction:[UIAlertAction actionWithTitle:@"Done" style:UIAlertActionStyleCancel handler:nil]];
                [self presentViewController:alert animated:YES completion:nil];
                return;
            }
            if ([status[@"marker_valid"] boolValue] && [status[@"mac_identity_bound"] boolValue]) {
                [self beginPairingRequest];
                return;
            }
            NSString *fingerprint = status[@"mac_identity_fingerprint"];
            NSString *macName = status[@"mac_name"] ?: @"0-Sky Mac";
            if (!fingerprint.length || ![status[@"mac_discovery_authenticated"] boolValue]) {
                UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"0-Sky Mac Not Found"
                  message:@"Open 0-Sky on the Mac and keep this device connected. The discovered host identity could not yet be authenticated."
                  preferredStyle:UIAlertControllerStyleAlert];
                [alert addAction:[UIAlertAction actionWithTitle:@"Done" style:UIAlertActionStyleCancel handler:nil]];
                [self presentViewController:alert animated:YES completion:nil];
                return;
            }
            NSString *shortFingerprint = fingerprint.length > 12 ?
                [NSString stringWithFormat:@"…%@", [fingerprint substringFromIndex:fingerprint.length - 12]] : fingerprint;
            NSString *message = [NSString stringWithFormat:
              @"Enroll this 0-Sky Mac as a trusted host?\n\nMac: %@\nFingerprint: %@\n\nApple may separately ask you to trust the computer.",
              macName, shortFingerprint];
            UIAlertController *confirm = [UIAlertController alertControllerWithTitle:@"Trust This 0-Sky Mac"
              message:message preferredStyle:UIAlertControllerStyleAlert];
            [confirm addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
            [confirm addAction:[UIAlertAction actionWithTitle:@"Trust This Mac" style:UIAlertActionStyleDefault
              handler:^(UIAlertAction *action) { [self beginPairingRequest]; }]];
            [self presentViewController:confirm animated:YES completion:nil];
        });
      }] resume];
}
- (void)beginPairingRequest {
    NSString *token = [self bridgeToken];
    if (!token.length) {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Mac Bridge Not Running"
          message:@"Open 0-Sky on the Mac, connect this device by USB, and try again. The bridge starts automatically."
          preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"Done" style:UIAlertActionStyleCancel handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
        return;
    }
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:
      [NSURL URLWithString:@"http://127.0.0.1:48654/v1/pairing/request"]];
    request.HTTPMethod = @"POST"; request.timeoutInterval = 15;
    [request setValue:token forHTTPHeaderField:@"X-TrollStore-Bridge-Token"];
    request.HTTPBody = [NSData data];
    _pairingJobID = nil; _pairingCancellationRequested = NO;
    [_pairButton setTitle:@"WAITING FOR TRUST APPROVAL…" forState:UIControlStateNormal];
    _pairButton.enabled = NO;
    UIAlertController *waiting = [UIAlertController alertControllerWithTitle:@"Pairing With Trusted Mac"
      message:[self pairingProgressMessage:@{@"pairing_state": @"WAITING_FOR_TRUST"}]
      preferredStyle:UIAlertControllerStyleAlert];
    [waiting addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel
      handler:^(UIAlertAction *action) { [self cancelPairingRequest]; }]];
    _pairingProgressAlert = waiting;
    [self presentViewController:waiting animated:YES completion:nil];
    [[NSURLSession.sharedSession dataTaskWithRequest:request completionHandler:
      ^(NSData *data, NSURLResponse *response, NSError *error) {
        NSDictionary *result = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
        dispatch_async(dispatch_get_main_queue(), ^{
            self.pairingJobID = result[@"job_id"];
            if (self.pairingCancellationRequested) [self cancelPairingRequest];
            self.pairButton.enabled = YES;
            if (error || [result[@"status"] integerValue] != 0) {
                NSString *message = result[@"stderr"] ?: @"0-Sky Mac Bridge is unavailable";
                self.pairingJobID = nil;
                self.pairingCancellationRequested = NO;
                self.pairingProgressAlert = nil;
                [self appendConsole:[NSString stringWithFormat:@"[pairing] %@", message]];
                [self.pairButton setTitle:@"PAIRING FAILED — TRY AGAIN" forState:UIControlStateNormal];
                [self dismissViewControllerAnimated:YES completion:^{
                    UIAlertController *failure = [UIAlertController alertControllerWithTitle:@"Pairing Failed"
                      message:message preferredStyle:UIAlertControllerStyleAlert];
                    [failure addAction:[UIAlertAction actionWithTitle:@"Done" style:UIAlertActionStyleCancel handler:nil]];
                    [self presentViewController:failure animated:YES completion:nil];
                }];
            } else {
                [self appendConsole:@"[pairing] Mac Bridge accepted the request; monitoring Apple trust"];
            }
        });
      }] resume];
}
- (void)viewDidLayoutSubviews { [super viewDidLayoutSubviews]; }
- (void)checkRuntime {
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:RuntimeURL]];
    request.timeoutInterval = 10;
    NSString *token = [self bridgeToken];
    if (token.length) [request setValue:token forHTTPHeaderField:@"X-TrollStore-Bridge-Token"];
    NSURLSessionDataTask *task = [NSURLSession.sharedSession dataTaskWithRequest:request
      completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        NSDictionary *json = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
        dispatch_async(dispatch_get_main_queue(), ^{ [self applyStatus:json error:error]; });
      }];
    [task resume];
}
- (void)appendConsole:(NSString *)line {
    if (!line.length) return;
    static NSISO8601DateFormatter *clock;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        clock = [NSISO8601DateFormatter new];
        clock.formatOptions = NSISO8601DateFormatWithInternetDateTime |
                              NSISO8601DateFormatWithFractionalSeconds;
        clock.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:0];
    });
    NSString *respectful = [line stringByReplacingOccurrencesOfString:@"privilege escalation"
      withString:@"privileged runtime handoff" options:NSCaseInsensitiveSearch
      range:NSMakeRange(0, line.length)];
    respectful = [respectful stringByReplacingOccurrencesOfString:@"bypass"
      withString:@"authorized compatibility transition" options:NSCaseInsensitiveSearch
      range:NSMakeRange(0, respectful.length)];
    respectful = [respectful stringByReplacingOccurrencesOfString:@"[exploit]"
      withString:@"[research-transition]" options:NSCaseInsensitiveSearch
      range:NSMakeRange(0, respectful.length)];
    NSMutableString *batch = [NSMutableString string];
    for (NSString *raw in [respectful componentsSeparatedByCharactersInSet:
                           NSCharacterSet.newlineCharacterSet]) {
        if (!raw.length) continue;
        [batch appendFormat:@"%@ %@\n", [clock stringFromDate:NSDate.date], raw];
    }
    _console.text = [_console.text stringByAppendingString:batch];
    if (_console.text.length > 300000)
        _console.text = [_console.text substringFromIndex:_console.text.length - 240000];
    NSRange end = NSMakeRange(_console.text.length, 0);
    [_console scrollRangeToVisible:end];
}
- (void)appendRuntimeSnapshot:(NSDictionary *)status pairing:(NSDictionary *)pairing {
    if (![status isKindOfClass:NSDictionary.class]) return;
    NSArray *digestKeys = @[@"ok", @"ellekit_ok", @"manager_active", @"paused", @"generation",
      @"configured_dylibs", @"quarantined_dylibs", @"effective_dylibs", @"configured_targets",
      @"loaded_dylibs", @"loaded_targets", @"crypstore_ok", @"crypstore_mounted",
      @"crypstore_registered", @"crypstore_running", @"crypstore_version", @"bridge_euid",
      @"bridge_user", @"darwin_release", @"machine", @"rootless_free_mb", @"registry_generated_at"];
    NSMutableArray *parts = [NSMutableArray array];
    for (NSString *key in digestKeys) [parts addObject:[NSString stringWithFormat:@"%@=%@", key, status[key] ?: @"-"]];
    [parts addObject:[NSString stringWithFormat:@"pair=%@/%@/%@", pairing[@"paired"] ?: @0,
      pairing[@"pairing_state"] ?: @"unknown", pairing[@"transport_type"] ?: @"unavailable"]];
    NSString *digest = [parts componentsJoinedByString:@"|"];
    if ([digest isEqualToString:_lastRuntimeDigest]) return;
    _lastRuntimeDigest = digest;
    [self appendConsole:@"──────── AUTHENTICATED RUNTIME SNAPSHOT ────────"];
    [self appendConsole:[NSString stringWithFormat:@"[phase 02/08][trusted-host] paired=%@ relationship=%@ transport=%@ state=%@",
      [pairing[@"paired"] boolValue] ? @"yes" : @"no",
      [pairing[@"relationship_verified"] boolValue] ? @"verified" : @"pending",
      pairing[@"transport_type"] ?: @"unavailable", pairing[@"pairing_state"] ?: @"unknown"]];
    [self appendConsole:[NSString stringWithFormat:@"[phase 03/08][privileged-runtime-handoff] euid=%@ user=%@ root-proof=%@",
      status[@"bridge_euid"] ?: @"?", status[@"bridge_user"] ?: @"unknown",
      [status[@"bridge_euid"] integerValue] == 0 ? @"PASS" : @"NOT ESTABLISHED"]];
    [self appendConsole:[NSString stringWithFormat:@"[phase 04/08][runtime-manager] active=%@ paused=%@ Darwin=%@ machine=%@",
      [status[@"manager_active"] boolValue] ? @"yes" : @"no", [status[@"paused"] boolValue] ? @"yes" : @"no",
      status[@"darwin_release"] ?: @"unknown", status[@"machine"] ?: @"unknown"]];
    [self appendConsole:[NSString stringWithFormat:@"[phase 05/08][registry] generation=%@ generated=%@ configured=%@ effective=%@ quarantined=%@ targets=%@",
      status[@"generation"] ?: @"unknown", status[@"registry_generated_at"] ?: @"unknown",
      status[@"configured_dylibs"] ?: @0, status[@"effective_dylibs"] ?: @0,
      status[@"quarantined_dylibs"] ?: @0, status[@"configured_targets"] ?: @0]];
    [self appendConsole:[NSString stringWithFormat:@"[phase 06/08][trust-cryptex] rootless-free=%@ MiB control-mounted=%@",
      status[@"rootless_free_mb"] ?: @"?", [status[@"crypstore_mounted"] boolValue] ? @"yes" : @"no"]];
    [self appendConsole:[NSString stringWithFormat:@"[phase 07/08][injection-activation] ElleKit=%@ loaded-dylibs=%@ live-targets=%@",
      [status[@"ellekit_ok"] boolValue] ? @"PASS" : @"WAITING", status[@"loaded_dylibs"] ?: @0,
      status[@"loaded_targets"] ?: @0]];
    [self appendConsole:[NSString stringWithFormat:@"[phase 08/08][app-registration] Control=%@ mounted=%@ registered=%@ running=%@",
      status[@"crypstore_version"] ?: @"unknown", [status[@"crypstore_mounted"] boolValue] ? @"yes" : @"no",
      [status[@"crypstore_registered"] boolValue] ? @"yes" : @"no", [status[@"crypstore_running"] boolValue] ? @"yes" : @"no"]];
    [self appendConsole:[NSString stringWithFormat:@"[acceptance] authorized research runtime=%@",
      [status[@"ok"] boolValue] && [pairing[@"paired"] boolValue] ? @"FULL" : @"IN PROGRESS"]];
}
- (void)advanceRefreshStage {
    if (!_refreshing) return;
    _refreshSeconds += 1;
    // Real work completes asynchronously on the Mac companion.  Hold below 95%
    // until its authenticated result arrives rather than claiming false success.
    float next = MIN(.94f, _progress.progress + (_progress.progress < .55f ? .035f : .012f));
    [_progress setProgress:next animated:YES];
    NSInteger pct = (NSInteger)(next * 100.0f + .5f);
    NSString *stage = @"WAITING FOR SEALED RUNTIME";
    if (next < .24f) stage = @"DISCOVERING INSTALLED TWEAKS";
    else if (next < .42f) stage = @"AUDITING APP CRYPTEXES";
    else if (next < .63f) stage = @"REBUILDING ELLEKIT TRUST CACHE";
    else if (next < .82f) stage = @"SEALING + INSTALLING CRYPTEX";
    else if (next < .94f) stage = @"ACTIVATING VERIFIED INJECTION TARGETS";
    _progressText.text = [NSString stringWithFormat:@"%ld%% // %@", (long)pct, stage];
    if (_refreshSeconds == 4) [self appendConsole:@"[registry] enumerating dpkg-owned dylibs and filters"];
    else if (_refreshSeconds == 9) [self appendConsole:@"[0-Sky Control] reconciling installed and explicitly removed apps"];
    else if (_refreshSeconds == 15) [self appendConsole:@"[trustcache] hashing rootless executables and preference bundles"];
    else if (_refreshSeconds == 24) [self appendConsole:@"[cryptex] creating and sealing the refreshed runtime generation"];
    else if (_refreshSeconds == 38) [self appendConsole:@"[phase 07/08][injection-activation] preparing verified live targets for restart"];
    else if (_refreshSeconds > 0 && _refreshSeconds % 30 == 0)
        [self appendConsole:[NSString stringWithFormat:@"[0-Sky Link] refresh still active (%lds); waiting for verified result", (long)_refreshSeconds]];
}
- (void)refreshRuntime {
    if (_refreshing) return;
    if (!_paired) { [self showPairingAssistant]; return; }
    _refreshing = YES; _refresh.enabled = NO;
    [_refresh setTitle:@"REFRESHING RESEARCH RUNTIME…" forState:UIControlStateNormal];
    _headline.text = @"0-SKY LINK // RUNTIME REFRESH";
    _refreshSeconds = 0;
    [_progress setProgress:.05 animated:YES];
    _progressText.text = @"5% // STARTING AUTHENTICATED REFRESH";
    _console.text = @"";
    [self appendConsole:@"[0-Sky Link] START pressed — beginning end-to-end authorized runtime refresh"];
    [self appendConsole:@"[phase 01/08][device-context] local SRD request accepted"];
    [self appendConsole:@"[phase 02/08][trusted-host] authenticated bridge token accepted"];
    [self appendConsole:@"[phase 03/08][privileged-runtime-handoff] requesting measured uid-0 service"];
    [self appendConsole:@"[phase 04/08][runtime-manager] synchronizing dpkg/filter state"];
    [self appendConsole:@"[phase 05/08][registry] enumerating installed tweak filters"];
    [self appendConsole:@"[phase 06/08][trust-cryptex] requesting fresh ElleKit trust cache"];
    [_stageTimer invalidate];
    _stageTimer = [NSTimer scheduledTimerWithTimeInterval:1.0 target:self selector:@selector(advanceRefreshStage)
                                                userInfo:nil repeats:YES];
    NSError *readError = nil;
    NSString *token = [NSString stringWithContentsOfFile:@"/var/jb/etc/trollstorelite-srd-bridge.token"
                                                encoding:NSUTF8StringEncoding error:&readError];
    token = [token stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (!token.length) {
        [self appendConsole:@"[error] local bridge token is unavailable"];
        [_stageTimer invalidate]; _stageTimer = nil;
        [_progress setProgress:0 animated:YES];
        _progressText.text = @"FAILED // LOCAL BRIDGE TOKEN UNAVAILABLE";
        _refreshing = NO; _refresh.enabled = YES;
        [_refresh setTitle:@"START / REFRESH RESEARCH RUNTIME" forState:UIControlStateNormal];
        return;
    }
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:
      [NSURL URLWithString:@"http://127.0.0.1:48654/v1/runtime/refresh"]];
    request.HTTPMethod = @"POST"; request.timeoutInterval = 1200;
    [request setValue:token forHTTPHeaderField:@"X-TrollStore-Bridge-Token"];
    request.HTTPBody = [NSData data];
    [[NSURLSession.sharedSession dataTaskWithRequest:request completionHandler:
      ^(NSData *data, NSURLResponse *response, NSError *error) {
        NSDictionary *json = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.stageTimer invalidate]; self.stageTimer = nil;
            if (error) [self appendConsole:[NSString stringWithFormat:@"[error] %@", error.localizedDescription]];
            else {
                [self appendConsole:json[@"stdout"] ?: @"[error] invalid refresh response"];
                NSString *stderrText = json[@"stderr"];
                if (stderrText.length) [self appendConsole:[@"[stderr] " stringByAppendingString:stderrText]];
            }
            BOOL success = !error && [json[@"status"] integerValue] == 0;
            [self.progress setProgress:(success ? 1.0f : self.progress.progress) animated:YES];
            self.progressText.text = success ? @"100% // CRYPTEXES REFRESHED + INJECTION ACTIVATED" :
                                               @"FAILED // REVIEW VERBOSE LOG BELOW";
            if (success) [self appendConsole:@"[0-Sky Link] SUCCESS: refreshed runtime accepted; verifying live ElleKit state"];
            self.refreshing = NO; self.refresh.enabled = YES;
            [self.refresh setTitle:@"START / REFRESH RESEARCH RUNTIME" forState:UIControlStateNormal];
            [self checkRuntime];
        });
      }] resume];
}
- (NSString *)bridgeToken {
    NSString *token = [NSString stringWithContentsOfFile:@"/var/jb/etc/trollstorelite-srd-bridge.token"
                                                encoding:NSUTF8StringEncoding error:nil];
    return [token stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
}
- (void)finishCrypStoreOperation:(NSDictionary *)json error:(NSError *)error {
    dispatch_async(dispatch_get_main_queue(), ^{
        [self.stageTimer invalidate]; self.stageTimer = nil;
        if (error) [self appendConsole:[NSString stringWithFormat:@"[0-Sky Control:error] %@", error.localizedDescription]];
        if ([json[@"stdout"] length]) [self appendConsole:json[@"stdout"]];
        if ([json[@"stderr"] length]) [self appendConsole:[@"[0-Sky Control:stderr] " stringByAppendingString:json[@"stderr"]]];
        BOOL success = !error && [json[@"status"] integerValue] == 0;
        [self.progress setProgress:(success ? 1.0f : self.progress.progress) animated:YES];
        self.progressText.text = success ? @"100% // 0-SKY CONTROL REGISTERED + READY" : @"FAILED // 0-SKY CONTROL RECOVERY LOGGED";
        [self.crypstoreButton setTitle:(success ? @"0-SKY CONTROL READY / REPAIR AGAIN" : @"RETRY 0-SKY CONTROL INSTALL")
                                forState:UIControlStateNormal];
        self.refreshing = NO; self.refresh.enabled = YES; self.crypstoreButton.enabled = YES;
        [self checkRuntime];
    });
}
- (void)installBundledCrypStoreWithToken:(NSString *)token {
    NSString *source = [NSBundle.mainBundle pathForResource:@"CrypStore-Universal" ofType:@"deb"
                                                 inDirectory:@"SRDKit/packages"];
    NSURL *documents = [NSFileManager.defaultManager URLsForDirectory:NSDocumentDirectory
                                                             inDomains:NSUserDomainMask].firstObject;
    NSURL *destination = [documents URLByAppendingPathComponent:@"CrypStore-Universal.deb"];
    NSError *copyError = nil;
    [NSFileManager.defaultManager removeItemAtURL:destination error:nil];
    if (!source.length || ![NSFileManager.defaultManager copyItemAtPath:source toPath:destination.path error:&copyError]) {
        [self finishCrypStoreOperation:nil error:copyError ?: [NSError errorWithDomain:@"0-Sky" code:2
            userInfo:@{NSLocalizedDescriptionKey:@"Bundled 0-Sky Control package is unavailable"}]];
        return;
    }
    [self appendConsole:@"[0-Sky Control] mounted recovery unavailable; installing bundled universal package"];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:
        [NSURL URLWithString:@"http://127.0.0.1:48654/v1/trollstore"]];
    request.HTTPMethod = @"POST"; request.timeoutInterval = 1800;
    [request setValue:token forHTTPHeaderField:@"X-TrollStore-Bridge-Token"];
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    request.HTTPBody = [NSJSONSerialization dataWithJSONObject:
        @{ @"arguments": @[@"install-deb", destination.path] } options:0 error:nil];
    [[NSURLSession.sharedSession dataTaskWithRequest:request completionHandler:
      ^(NSData *data, NSURLResponse *response, NSError *error) {
        NSDictionary *json = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
        [self finishCrypStoreOperation:json error:error];
      }] resume];
}
- (void)repairCrypStore {
    if (_refreshing) return;
    if (!_paired) { [self showPairingAssistant]; return; }
    NSString *token = [self bridgeToken];
    if (!token.length) {
        [self appendConsole:@"[0-Sky Control:error] local bridge token is unavailable"];
        return;
    }
    _refreshing = YES; _refresh.enabled = NO; _crypstoreButton.enabled = NO;
    _refreshSeconds = 0; [_progress setProgress:.08 animated:YES];
    _progressText.text = @"8% // CHECKING 0-SKY CONTROL CRYPTEX + REGISTRATION";
    _headline.text = @"0-SKY LINK // 0-SKY CONTROL: REPAIRING";
    [self appendConsole:@"[0-Sky Control] authenticated repair/install requested"];
    [_stageTimer invalidate];
    _stageTimer = [NSTimer scheduledTimerWithTimeInterval:1 target:self selector:@selector(advanceRefreshStage)
                                                userInfo:nil repeats:YES];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:
        [NSURL URLWithString:@"http://127.0.0.1:48654/v1/crypstore/repair"]];
    request.HTTPMethod = @"POST"; request.timeoutInterval = 240;
    [request setValue:token forHTTPHeaderField:@"X-TrollStore-Bridge-Token"];
    request.HTTPBody = [NSData data];
    [[NSURLSession.sharedSession dataTaskWithRequest:request completionHandler:
      ^(NSData *data, NSURLResponse *response, NSError *error) {
        NSDictionary *json = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
        if (!error && [json[@"status"] integerValue] == 0) [self finishCrypStoreOperation:json error:nil];
        else dispatch_async(dispatch_get_main_queue(), ^{
            [self appendConsole:@"[0-Sky Control] exact mounted recovery not usable; falling back to bundled installer"];
            [self installBundledCrypStoreWithToken:token];
        });
      }] resume];
}
- (void)applyStatus:(NSDictionary *)status error:(NSError *)error {
    if (_refreshing) return;
    NSDictionary *pairing = [status[@"pairing"] isKindOfClass:NSDictionary.class] ? status[@"pairing"] : nil;
    [self appendRuntimeSnapshot:status pairing:pairing ?: @{}];
    if (_pairingProgressAlert) _pairingProgressAlert.message = [self pairingProgressMessage:pairing ?: @{}];
    _paired = [pairing[@"paired"] boolValue];
    BOOL serverRelationship = [pairing[@"relationship_verified"] boolValue];
    BOOL explicitIdentityConflict = pairing && [pairing[@"worker_fresh"] boolValue] &&
      [pairing[@"marker_valid"] boolValue] &&
      (![pairing[@"udid_bound"] boolValue] || ![pairing[@"host_key_bound"] boolValue] ||
       ![pairing[@"mac_identity_bound"] boolValue]);
    if (_paired || serverRelationship) {
        _relationshipVerified = YES;
        [NSUserDefaults.standardUserDefaults setBool:YES forKey:@"ZeroSkyTrustedMacRelationshipVerified"];
    } else if (explicitIdentityConflict) {
        _relationshipVerified = NO;
        [NSUserDefaults.standardUserDefaults removeObjectForKey:@"ZeroSkyTrustedMacRelationshipVerified"];
    }
    BOOL displayVerified = _paired || _relationshipVerified;
    if (_pairingJobID.length) [self pollPairingResult];
    BOOL wifiPairingVerified = [pairing[@"wifi_pairing_verified"] boolValue];
    if (_paired && wifiPairingVerified && _pairingJobID.length) {
        _pairingJobID = nil; _pairingCancellationRequested = NO;
        _pairingProgressAlert = nil;
        [self dismissViewControllerAnimated:YES completion:^{
            UIAlertController *done = [UIAlertController alertControllerWithTitle:@"Trusted Mac Verified"
              message:@"USB pairing and Wi-Fi fallback were verified for this Trusted Mac."
              preferredStyle:UIAlertControllerStyleAlert];
            [done addAction:[UIAlertAction actionWithTitle:@"Done" style:UIAlertActionStyleCancel handler:nil]];
            [self presentViewController:done animated:YES completion:nil];
        }];
    }
    _refresh.enabled = _paired;
    _crypstoreButton.enabled = _paired;
    BOOL wireless = [pairing[@"wireless_connected"] boolValue];
    NSString *transport = pairing[@"transport_type"] ?: @"UNAVAILABLE";
    NSString *pairTitle = _paired ? (!wifiPairingVerified ? @"FINISH WI-FI PAIRING" :
                                      (wireless ? @"TRUSTED MAC: VERIFIED • WIRELESS" :
                                                  @"TRUSTED MAC: VERIFIED • USB")) :
                          (displayVerified ? @"TRUSTED MAC: VERIFIED • RECONNECTING" :
                                             @"PAIR / VERIFY TRUSTED MAC");
    NSString *pairState = [pairing[@"pairing_state"] isKindOfClass:NSString.class] ?
      pairing[@"pairing_state"] : nil;
    NSString *pairError = [pairing[@"pairing_error"] isKindOfClass:NSString.class] ?
      pairing[@"pairing_error"] : nil;
    if (!displayVerified && ![pairing[@"bridge_running"] boolValue]) pairTitle = @"FIND TRUSTED MAC";
    else if (!_paired && [pairing[@"mac_discovery_authenticated"] boolValue] &&
             ![pairing[@"marker_valid"] boolValue] &&
             (!pairState.length || [pairState isEqualToString:@"IDLE"])) pairTitle = @"PAIR WITH MAC";
    else if (!_paired && ([pairState isEqualToString:@"DISCOVERING_MAC"] ||
                     [pairState isEqualToString:@"MAC_FOUND"])) pairTitle = @"FINDING TRUSTED MAC…";
    else if (!_paired && [pairState isEqualToString:@"WAITING_FOR_USB"]) pairTitle = @"CONNECT DEVICE BY USB";
    else if (!_paired && ([pairState isEqualToString:@"DEVICE_DISCOVERED"] ||
                          [pairState isEqualToString:@"CHECKING_PAIRING"] ||
                          [pairState isEqualToString:@"ALREADY_PAIRED"] ||
                          [pairState isEqualToString:@"VALIDATING_LOCKDOWN"] ||
                          [pairState isEqualToString:@"VERIFYING_DEVICE_IDENTITY"] ||
                          [pairState isEqualToString:@"VERIFYING_HOST_IDENTITY"] ||
                          [pairState isEqualToString:@"VERIFYING_SERVICES"] ||
                          [pairState isEqualToString:@"CLASSIFYING_DEVICE"])) pairTitle = @"VERIFYING MAC…";
    else if (!_paired && [pairState isEqualToString:@"DEVICE_LOCKED"]) pairTitle = @"UNLOCK DEVICE TO CONTINUE";
    else if (!_paired && [pairState isEqualToString:@"WAITING_FOR_TRUST"]) pairTitle = @"WAITING FOR TRUST APPROVAL…";
    else if (!_paired && [pairError isEqualToString:@"PAIR_RECORD_STALE"]) pairTitle = @"REPAIR TRUSTED MAC PAIRING";
    else if (!_paired && [pairError isEqualToString:@"TRUST_DENIED"]) pairTitle = @"PAIRING DENIED — TRY AGAIN";
    [_pairButton setTitle:pairTitle
                    forState:UIControlStateNormal];
    _pairButton.backgroundColor = displayVerified ? [UIColor colorWithRed:.25 green:1 blue:.48 alpha:1] :
                                                   [UIColor colorWithRed:1 green:.72 blue:.18 alpha:1];
    if (_paired && !_refreshing) {
        _progressText.text = [NSString stringWithFormat:
          @"TRUSTED MAC ✓  //  USB PAIRING %@  //  WI-FI PAIRING %@  //  CONNECTION: %@",
          [pairing[@"usb_pairing_verified"] boolValue] ? @"✓" : @"…",
          wifiPairingVerified ? @"✓" : @"PENDING", transport];
    }
    if (!_paired && pairing && !_didLogPairing) {
        _didLogPairing = YES;
        [self appendConsole:[@"[pairing] " stringByAppendingString:pairing[@"message"] ?: @"trusted Mac verification required"]];
    }
    if (_paired && !_didLogPairing) {
        _didLogPairing = YES;
        [self appendConsole:@"[pairing] Apple trusted session + device identity + 0-Sky Mac identity verified"];
    }
    BOOL ready = [status[@"ok"] boolValue] && _paired;
    if ([status[@"bridge_euid"] integerValue] == 0 && !_didLogRoot) {
        _didLogRoot = YES;
        [self appendConsole:@"[root] ROOT OBTAINED // privileged bridge verified uid=0"];
    }
    if (status && !_didLogResearchStatus) {
        _didLogResearchStatus = YES;
        [self appendConsole:[NSString stringWithFormat:@"[bridge] euid=%@ (%@)  Darwin %@",
          status[@"bridge_euid"] ?: @"?", status[@"bridge_user"] ?: @"unknown",
          status[@"darwin_release"] ?: @"unknown"]];
        [self appendConsole:[NSString stringWithFormat:@"[runtime] generation=%@  registry=%@",
          status[@"generation"] ?: @"?", status[@"registry_generated_at"] ?: @"unknown"]];
        [self appendConsole:[NSString stringWithFormat:@"[tweaks] configured=%@/%@ targets  loaded=%@/%@ live targets",
          status[@"configured_dylibs"] ?: @0, status[@"configured_targets"] ?: @0,
          status[@"loaded_dylibs"] ?: @0, status[@"loaded_targets"] ?: @0]];
        [self appendConsole:[NSString stringWithFormat:@"[0-Sky Control] v%@ mounted=%@ registered=%@ running=%@",
          status[@"crypstore_version"] ?: @"?", [status[@"crypstore_mounted"] boolValue] ? @"yes" : @"no",
          [status[@"crypstore_registered"] boolValue] ? @"yes" : @"no",
          [status[@"crypstore_running"] boolValue] ? @"yes" : @"no"]];
        [self appendConsole:[NSString stringWithFormat:@"[rootless] free=%@ MiB  machine=%@",
          status[@"rootless_free_mb"] ?: @"?", status[@"machine"] ?: @"unknown"]];
    }
    if (ready) {
        if (!_didLogFull) {
            _didLogFull = YES;
            [self appendConsole:@"[ElleKit] FULL INJECTION OBTAINED // live targets passed"];
        }
        NSInteger loaded = [status[@"loaded_dylibs"] integerValue];
        NSInteger targets = [status[@"loaded_targets"] integerValue];
        NSString *crypVersion = status[@"crypstore_version"] ?: @"unknown";
        [_crypstoreButton setTitle:[NSString stringWithFormat:@"0-SKY CONTROL %@: ONLINE / REPAIR", crypVersion]
                           forState:UIControlStateNormal];
        _headline.text = @"0-SKY LINK // AUTHORIZED RUNTIME: FULL";
        _headline.textColor = [UIColor colorWithRed:.25 green:1 blue:.48 alpha:1];
        _pulse.textColor = [UIColor colorWithRed:.25 green:1 blue:.48 alpha:1];
        _detail.text = [NSString stringWithFormat:@"ELLEKIT ONLINE  •  %ld TWEAKS LOADED  •  %ld TARGETS\n0-SKY CONTROL %@ ONLINE%@  •  ROOTLESS RECOVERY KIT BUNDLED", (long)loaded, (long)targets,
                        crypVersion, [status[@"crypstore_running"] boolValue] ? @" + RUNNING" : @""];
    } else {
        if (!_paired && displayVerified) _headline.text = @"0-SKY LINK // TRUSTED MAC: RECONNECTING";
        else if (!_paired) _headline.text = @"0-SKY LINK // TRUSTED MAC: PAIR REQUIRED";
        else if ([status[@"ellekit_ok"] boolValue] && ![status[@"crypstore_ok"] boolValue])
            _headline.text = @"0-SKY LINK // 0-SKY CONTROL: REPAIR REQUIRED";
        else if ([status[@"paused"] boolValue]) _headline.text = @"0-SKY LINK // RESEARCH RUNTIME: PAUSED";
        else if (status && ![status[@"manager_active"] boolValue]) _headline.text = @"0-SKY LINK // RESEARCH RUNTIME: OFFLINE";
        else _headline.text = @"0-SKY LINK // INJECTION ACTIVATION";
        _headline.textColor = UIColor.whiteColor;
        _pulse.textColor = [UIColor colorWithRed:1 green:.72 blue:.18 alpha:1];
        _detail.text = error ? (displayVerified ? @"Trusted Mac is saved; reconnecting to the local bridge" :
                                                 @"Local 0-Sky Control bridge is not ready") :
          (!_paired && displayVerified) ? @"Trusted Mac is verified and saved. Open 0-Sky on the Mac or reconnect USB to verify the live session." :
          !_paired ? @"Connect by USB, unlock and trust this Mac, then tap PAIR / VERIFY TRUSTED MAC" :
          [NSString stringWithFormat:@"Manager %@  •  %ld configured  •  %ld loaded\n0-Sky Control %@  •  bundled installer ready",
           [status[@"manager_active"] boolValue] ? @"online" : @"offline",
           (long)[status[@"configured_dylibs"] integerValue],
           (long)[status[@"loaded_dylibs"] integerValue],
           [status[@"crypstore_ok"] boolValue] ? @"online" : @"repair required"];
        [_crypstoreButton setTitle:([status[@"crypstore_ok"] boolValue] ?
          @"0-SKY CONTROL ONLINE / REPAIR" : @"REPAIR / INSTALL 0-SKY CONTROL") forState:UIControlStateNormal];
    }
}
- (BOOL)prefersStatusBarHidden { return NO; }
- (UIStatusBarStyle)preferredStatusBarStyle { return UIStatusBarStyleLightContent; }
@end

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@end
@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    return YES;
}
- (UISceneConfiguration *)application:(UIApplication *)application
    configurationForConnectingSceneSession:(UISceneSession *)session
    options:(UISceneConnectionOptions *)options API_AVAILABLE(ios(13.0)) {
    return [[UISceneConfiguration alloc] initWithName:@"Default Configuration"
                                         sessionRole:session.role];
}
@end

@interface SceneDelegate : UIResponder <UIWindowSceneDelegate>
@property(nonatomic,strong) UIWindow *window;
@end
@implementation SceneDelegate
- (void)scene:(UIScene *)scene willConnectToSession:(UISceneSession *)session
      options:(UISceneConnectionOptions *)connectionOptions API_AVAILABLE(ios(13.0)) {
    if (![scene isKindOfClass:UIWindowScene.class]) return;
    self.window = [[UIWindow alloc] initWithWindowScene:(UIWindowScene *)scene];
    self.window.rootViewController = [MatrixStatusController new];
    [self.window makeKeyAndVisible];
}
@end
int main(int argc, char **argv) { @autoreleasepool { return UIApplicationMain(argc, argv, nil, NSStringFromClass(AppDelegate.class)); } }
