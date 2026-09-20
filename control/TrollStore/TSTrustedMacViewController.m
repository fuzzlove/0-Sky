#import "TSTrustedMacViewController.h"

static NSString *const TSPairingStatusURL = @"http://127.0.0.1:48654/v1/pairing/status";

@interface TSTrustedMacViewController ()
@property(nonatomic,strong) NSDictionary *status;
@property(nonatomic,strong) NSTimer *timer;
@property(nonatomic,copy) NSString *jobID;
@property(nonatomic,assign) BOOL operationActive;
@property(nonatomic,assign) BOOL resultPollActive;
@property(nonatomic,assign) BOOL cancellationRequested;
@property(nonatomic,strong) UIAlertController *progressAlert;
@property(nonatomic,assign) BOOL relationshipVerified;
@end

@implementation TSTrustedMacViewController

- (instancetype)init { return [super initWithStyle:UITableViewStyleInsetGrouped]; }

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.title = @"Trusted Mac";
    self.navigationItem.largeTitleDisplayMode = UINavigationItemLargeTitleDisplayModeNever;
    self.relationshipVerified = [NSUserDefaults.standardUserDefaults boolForKey:@"ZeroSkyTrustedMacRelationshipVerified"];
    [self refreshStatus];
    self.timer = [NSTimer scheduledTimerWithTimeInterval:2 target:self
        selector:@selector(refreshStatus) userInfo:nil repeats:YES];
}

- (void)dealloc { [self.timer invalidate]; }

- (NSString*)bridgeToken
{
    NSString *value = [NSString stringWithContentsOfFile:
        @"/var/jb/etc/trollstorelite-srd-bridge.token" encoding:NSUTF8StringEncoding error:nil];
    return [value stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
}

- (void)refreshStatus
{
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:TSPairingStatusURL]];
    request.timeoutInterval = 10;
    NSString *token = [self bridgeToken];
    if(token.length) [request setValue:token forHTTPHeaderField:@"X-TrollStore-Bridge-Token"];
    [[NSURLSession.sharedSession dataTaskWithRequest:request
      completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        NSDictionary *value = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
        dispatch_async(dispatch_get_main_queue(), ^{
            if(value) {
                BOOL live = [value[@"paired"] boolValue];
                BOOL durable = [value[@"relationship_verified"] boolValue];
                BOOL conflict = [value[@"worker_fresh"] boolValue] && [value[@"marker_valid"] boolValue] &&
                  (![value[@"udid_bound"] boolValue] || ![value[@"host_key_bound"] boolValue] ||
                   ![value[@"mac_identity_bound"] boolValue]);
                if(live || durable) {
                    self.relationshipVerified = YES;
                    [NSUserDefaults.standardUserDefaults setBool:YES forKey:@"ZeroSkyTrustedMacRelationshipVerified"];
                } else if(conflict) {
                    self.relationshipVerified = NO;
                    [NSUserDefaults.standardUserDefaults removeObjectForKey:@"ZeroSkyTrustedMacRelationshipVerified"];
                }
                self.status = value;
            } else {
                // Preserve the last authenticated relationship across a
                // temporary bridge/worker outage. This is display-only.
                self.status = @{ @"message": @"0-Sky Mac Bridge is reconnecting",
                                 @"pairing_error": @"BRIDGE_NOT_RUNNING" };
            }
            [self updateProgressAlert];
            if(self.operationActive && [self.status[@"paired"] boolValue] &&
               [self.status[@"wifi_pairing_verified"] boolValue]) {
                self.operationActive = NO; self.jobID = nil;
                self.cancellationRequested = NO;
                self.progressAlert = nil;
                [self dismissViewControllerAnimated:YES completion:^{
                    UIAlertController *done = [UIAlertController alertControllerWithTitle:@"Trusted Mac Verified"
                      message:@"USB pairing and Wi-Fi fallback were verified. Bluetooth fallback is available after enabling it in Settings and approving Bluetooth access."
                      preferredStyle:UIAlertControllerStyleAlert];
                    [done addAction:[UIAlertAction actionWithTitle:@"Done" style:UIAlertActionStyleCancel handler:nil]];
                    [self presentViewController:done animated:YES completion:nil];
                }];
            }
            [self.tableView reloadData];
            if(self.operationActive && self.jobID.length) [self refreshOperationResult];
        });
      }] resume];
}

- (NSString*)pairingProgressMessage
{
    NSString *state = [self.status[@"pairing_state"] isKindOfClass:NSString.class] ?
        self.status[@"pairing_state"] : @"DISCOVERING_MAC";
    NSArray *ordered = @[@"DISCOVERING_MAC", @"MAC_FOUND", @"WAITING_FOR_USB",
        @"DEVICE_DISCOVERED", @"CHECKING_PAIRING", @"ALREADY_PAIRED",
        @"PAIRING_REQUIRED", @"REQUESTING_PAIR", @"WAITING_FOR_TRUST",
        @"VALIDATING_LOCKDOWN", @"VERIFYING_DEVICE_IDENTITY",
        @"VERIFYING_HOST_IDENTITY", @"VERIFYING_SERVICES", @"CLASSIFYING_DEVICE",
        @"VERIFIED_TRUSTED", @"WIRELESS_ENABLING", @"WIRELESS_WAITING_FOR_DISCONNECT",
        @"WIRELESS_DISCOVERING", @"WIRELESS_VERIFYING", @"WIRELESS_READY"];
    NSInteger position = [ordered indexOfObject:state];
    if([state isEqualToString:@"DEVICE_LOCKED"])
        position = [ordered indexOfObject:@"WAITING_FOR_TRUST"];
    if(position == NSNotFound) position = 0;
    BOOL mac = position >= [ordered indexOfObject:@"MAC_FOUND"];
    BOOL usb = position >= [ordered indexOfObject:@"DEVICE_DISCOVERED"];
    BOOL identified = position >= [ordered indexOfObject:@"CHECKING_PAIRING"];
    BOOL apple = position >= [ordered indexOfObject:@"VALIDATING_LOCKDOWN"];
    BOOL session = position >= [ordered indexOfObject:@"VERIFYING_HOST_IDENTITY"];
    BOOL host = position >= [ordered indexOfObject:@"VERIFYING_SERVICES"];
    BOOL capabilities = position >= [ordered indexOfObject:@"VERIFIED_TRUSTED"];
    BOOL wifiEnabled = position >= [ordered indexOfObject:@"WIRELESS_WAITING_FOR_DISCONNECT"];
    BOOL wifiVerified = [self.status[@"wifi_pairing_verified"] boolValue] ||
        position >= [ordered indexOfObject:@"WIRELESS_READY"];
    NSString *(^line)(BOOL, NSString*) = ^NSString *(BOOL done, NSString *title) {
        return [NSString stringWithFormat:@"%@ %@", done ? @"✓" : @"○", title];
    };
    NSString *instruction = @"0-Sky is monitoring the authenticated Mac Bridge.";
    if([state isEqualToString:@"WAITING_FOR_USB"])
        instruction = @"Connect this iPhone or iPad to the Mac by USB.";
    else if([state isEqualToString:@"DEVICE_LOCKED"])
        instruction = @"Unlock this device. Verification resumes automatically.";
    else if([state isEqualToString:@"WAITING_FOR_TRUST"])
        instruction = @"Unlock the device, tap Trust in Apple’s dialog, and enter the passcode if requested.";
    else if([state isEqualToString:@"WIRELESS_WAITING_FOR_DISCONNECT"])
        instruction = @"Disconnect the USB cable. 0-Sky will test the Wi-Fi fallback automatically.";
    else if([state hasPrefix:@"WIRELESS_"])
        instruction = @"Testing the authenticated wireless connection…";
    return [NSString stringWithFormat:@"%@\n\n%@\n%@\n%@\n%@\n%@\n%@\n%@\n%@\n%@",
        instruction, line(mac, @"Mac discovered"), line(usb, @"USB connection"),
        line(identified, @"Device identified"), line(apple, @"Apple pairing"),
        line(session, @"Trusted session"), line(host, @"0-Sky host"),
        line(capabilities, @"Capabilities checked"), line(wifiEnabled, @"Wi-Fi access enabled"),
        line(wifiVerified, @"Wi-Fi fallback verified")];
}

- (void)updateProgressAlert
{
    if(self.operationActive && self.progressAlert)
        self.progressAlert.message = [self pairingProgressMessage];
}

- (void)refreshOperationResult
{
    if(self.resultPollActive || !self.jobID.length) return;
    NSString *token = [self bridgeToken];
    if(!token.length) return;
    self.resultPollActive = YES;
    NSString *escaped = [self.jobID stringByAddingPercentEncodingWithAllowedCharacters:
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
            self.resultPollActive = NO;
            if(error || ![value[@"complete"] boolValue]) return;
            NSDictionary *result = [value[@"result"] isKindOfClass:NSDictionary.class] ? value[@"result"] : value;
            NSInteger code = [result[@"status"] integerValue];
            if(code == 0) return; // Global verified postconditions still decide success.
            NSString *errorCode = result[@"errorCode"];
            NSDictionary *pairing = [result[@"pairing"] isKindOfClass:NSDictionary.class] ? result[@"pairing"] : @{};
            NSString *message = pairing[@"userMessage"] ?: result[@"stderr"] ?: @"Trusted Mac verification failed.";
            self.operationActive = NO; self.jobID = nil;
            self.cancellationRequested = NO;
            self.progressAlert = nil;
            if([errorCode isEqualToString:@"CANCELLED"] || code == 130) {
                [self.tableView reloadData];
                return;
            }
            [self dismissViewControllerAnimated:YES completion:^{
                UIAlertController *failure = [UIAlertController alertControllerWithTitle:@"Pairing Failed"
                  message:message preferredStyle:UIAlertControllerStyleAlert];
                [failure addAction:[UIAlertAction actionWithTitle:@"Done" style:UIAlertActionStyleCancel handler:nil]];
                [self presentViewController:failure animated:YES completion:nil];
            }];
        });
      }] resume];
}

- (NSString*)actionTitle
{
    // Trust and transport are independent. A live verified USB relationship
    // is still a verified Trusted Mac; lack of wireless connectivity must not
    // relabel it as a failed relationship that needs re-pairing.
    if([self.status[@"paired"] boolValue] &&
       ![self.status[@"wifi_pairing_verified"] boolValue]) return @"Finish Wi-Fi Pairing";
    if([self.status[@"paired"] boolValue]) return @"Trusted Mac Verified";
    if(self.relationshipVerified) return @"Trusted Mac Verified • Reconnect";
    if(![self.status[@"bridge_running"] boolValue]) return @"Find Trusted Mac";
    NSString *state = [self.status[@"pairing_state"] isKindOfClass:NSString.class] ?
        self.status[@"pairing_state"] : nil;
    NSString *pairingError = [self.status[@"pairing_error"] isKindOfClass:NSString.class] ?
        self.status[@"pairing_error"] : nil;
    if([state isEqual:@"DEVICE_LOCKED"]) return @"Unlock Device to Continue";
    if([state isEqual:@"WAITING_FOR_TRUST"]) return @"Waiting for Trust Approval…";
    if([state hasPrefix:@"VERIFYING_"] || [state isEqual:@"VALIDATING_LOCKDOWN"])
        return @"Verifying Mac…";
    if([pairingError isEqual:@"PAIR_RECORD_STALE"])
        return @"Repair Trusted Mac Pairing";
    if(self.operationActive) return @"Pairing…";
    if([self.status[@"mac_discovery_authenticated"] boolValue] &&
       ![self.status[@"marker_valid"] boolValue]) return @"Pair With Mac";
    if(pairingError.length) return @"Pairing Failed";
    return @"Pair / Verify Trusted Mac";
}

- (NSInteger)numberOfSectionsInTableView:(UITableView*)tableView { (void)tableView; return 4; }
- (NSInteger)tableView:(UITableView*)tableView numberOfRowsInSection:(NSInteger)section
{ (void)tableView; return section == 0 ? 6 : section == 1 ? 4 : section == 2 ? 1 : 10; }

- (NSString*)tableView:(UITableView*)tableView titleForHeaderInSection:(NSInteger)section
{
    (void)tableView;
    return @[@"TRUST", @"DEVICE AND MAC", @"ACTION", @"ADVANCED DIAGNOSTICS"][section];
}

- (UITableViewCell*)valueCell:(NSString*)title value:(NSString*)value
{
    UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:nil];
    cell.textLabel.text = title; cell.detailTextLabel.text = value ?: @"Unavailable";
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    cell.detailTextLabel.adjustsFontSizeToFitWidth = YES;
    return cell;
}

- (UITableViewCell*)tableView:(UITableView*)tableView cellForRowAtIndexPath:(NSIndexPath*)indexPath
{
    (void)tableView;
    NSDictionary *device = [self.status[@"device"] isKindOfClass:NSDictionary.class] ? self.status[@"device"] : @{};
    NSDictionary *remote = [self.status[@"remote_services"] isKindOfClass:NSDictionary.class] ? self.status[@"remote_services"] : @{};
    if(indexPath.section == 0) {
        if(indexPath.row == 0) return [self valueCell:@"Trusted Mac"
            value:[self.status[@"paired"] boolValue] ? @"Verified" :
                  (self.relationshipVerified ? @"Verified • Reconnecting" : @"Not Verified")];
        if(indexPath.row == 1) return [self valueCell:@"USB Pairing"
            value:[self.status[@"usb_pairing_verified"] boolValue] ? @"✓ Verified" : @"Not Verified"];
        if(indexPath.row == 2) return [self valueCell:@"Wi-Fi Pairing"
            value:[self.status[@"wifi_pairing_verified"] boolValue] ? @"✓ Verified" :
                  ([self.status[@"wifi_lockdown_enabled"] boolValue] ? @"Enabled • Verification Pending" : @"Not Configured")];
        if(indexPath.row == 3) return [self valueCell:@"Bluetooth Pairing"
            value:[self.status[@"bluetooth_pairing_verified"] boolValue] ? @"✓ Verified" :
                  ([self.status[@"bluetooth_connected"] boolValue] ? @"Authenticating" : @"Standby")];
        if(indexPath.row == 4) return [self valueCell:@"Connection"
            value:self.status[@"transport_type"] ?: @"Offline"];
        return [self valueCell:@"Remote Services"
            value:self.status[@"remote_pairing_state"] ?: @"Not Configured"];
    }
    if(indexPath.section == 1) {
        NSArray *titles = @[@"Device", @"OS", @"Mac", @"Last Verified"];
        NSArray *values = @[device[@"productType"] ?: @"Unknown",
            device[@"productVersion"] ?: @"Unknown", self.status[@"mac_name"] ?: @"Unknown",
            [self.status[@"last_verified_at"] description] ?: @"Never"];
        return [self valueCell:titles[indexPath.row] value:values[indexPath.row]];
    }
    if(indexPath.section == 2) {
        UITableViewCell *cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
        cell.textLabel.text = [self actionTitle]; cell.textLabel.textAlignment = NSTextAlignmentCenter;
        cell.textLabel.textColor = self.relationshipVerified || [self.status[@"paired"] boolValue] ?
            [UIColor colorWithRed:.10 green:.72 blue:.28 alpha:1] : self.view.tintColor;
        cell.selectionStyle = UITableViewCellSelectionStyleDefault;
        return cell;
    }
    NSString *fingerprint = self.status[@"mac_identity_fingerprint"] ?: @"Unavailable";
    if(fingerprint.length > 18) fingerprint = [@"…" stringByAppendingString:
        [fingerprint substringFromIndex:fingerprint.length - 18]];
    NSArray *titles = @[@"Apple Pairing", @"Trusted Session", @"0-Sky Host Identity",
        @"Remote Services", @"Bridge Installed", @"Bridge Running", @"Device Backend",
        @"Bridge Version", @"Protocol Version", @"Research Class"];
    NSArray *values = @[
        [self.status[@"apple_pairing_verified"] boolValue] ? @"PASS" : @"FAIL",
        [self.status[@"lockdown_session_validated"] boolValue] ? @"PASS" : @"FAIL",
        [self.status[@"host_identity_verified"] boolValue] ? [@"PASS " stringByAppendingString:fingerprint] : @"FAIL",
        remote[@"status"] ?: @"NOT REQUIRED",
        [self.status[@"bridge_installed"] boolValue] ? @"YES" : @"NO",
        [self.status[@"bridge_running"] boolValue] ? @"YES" : @"NO",
        self.status[@"device_backend"] ?: @"Unknown",
        self.status[@"bridge_version"] ?: @"Unknown",
        [self.status[@"protocol_version"] description] ?: @"Unknown",
        self.status[@"research_class"] ?: @"UNKNOWN"];
    return [self valueCell:titles[indexPath.row] value:values[indexPath.row]];
}

- (void)tableView:(UITableView*)tableView didSelectRowAtIndexPath:(NSIndexPath*)indexPath
{
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if(indexPath.section == 2) [self confirmOrBeginPairing];
}

- (void)confirmOrBeginPairing
{
    if(self.operationActive) return;
    if([self.status[@"marker_valid"] boolValue] && [self.status[@"mac_identity_bound"] boolValue]) {
        [self beginPairing]; return;
    }
    NSString *fingerprint = self.status[@"mac_identity_fingerprint"];
    if(!fingerprint.length || ![self.status[@"mac_discovery_authenticated"] boolValue]) {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"0-Sky Mac Not Found"
          message:@"Connect this device to the Mac and open 0-Sky. The discovered host identity could not yet be authenticated."
          preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"Done" style:UIAlertActionStyleCancel handler:nil]];
        [self presentViewController:alert animated:YES completion:nil]; return;
    }
    NSString *shortFingerprint = fingerprint.length > 12 ? [@"…" stringByAppendingString:
        [fingerprint substringFromIndex:fingerprint.length - 12]] : fingerprint;
    NSString *message = [NSString stringWithFormat:@"Enroll %@ as a trusted 0-Sky host?\n\nFingerprint: %@\n\nApple may separately request device trust and your passcode.",
        self.status[@"mac_name"] ?: @"this Mac", shortFingerprint];
    UIAlertController *confirm = [UIAlertController alertControllerWithTitle:@"Trust This 0-Sky Mac"
      message:message preferredStyle:UIAlertControllerStyleAlert];
    [confirm addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    [confirm addAction:[UIAlertAction actionWithTitle:@"Trust This Mac" style:UIAlertActionStyleDefault
      handler:^(UIAlertAction *action) { [self beginPairing]; }]];
    [self presentViewController:confirm animated:YES completion:nil];
}

- (void)beginPairing
{
    NSString *token = [self bridgeToken];
    if(!token.length) {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"0-Sky Mac Not Found"
          message:@"Open 0-Sky on the Mac and keep this device connected."
          preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"Done" style:UIAlertActionStyleCancel handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
        return;
    }
    self.operationActive = YES;
    self.cancellationRequested = NO;
    [self.tableView reloadData];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:
        [NSURL URLWithString:@"http://127.0.0.1:48654/v1/pairing/request"]];
    request.HTTPMethod = @"POST"; request.timeoutInterval = 15; request.HTTPBody = NSData.data;
    [request setValue:token forHTTPHeaderField:@"X-TrollStore-Bridge-Token"];
    [[NSURLSession.sharedSession dataTaskWithRequest:request completionHandler:
      ^(NSData *data, NSURLResponse *response, NSError *error) {
        NSDictionary *result = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
        dispatch_async(dispatch_get_main_queue(), ^{
            self.jobID = result[@"job_id"];
            if(self.cancellationRequested && self.jobID.length) {
                [self cancelPairing];
                return;
            }
            if(error || [result[@"status"] integerValue] != 0) {
                self.operationActive = NO;
                self.cancellationRequested = NO;
                UIAlertController *failure = [UIAlertController alertControllerWithTitle:@"Pairing Failed"
                  message:result[@"stderr"] ?: @"The Mac Bridge is unavailable."
                  preferredStyle:UIAlertControllerStyleAlert];
                [failure addAction:[UIAlertAction actionWithTitle:@"Done" style:UIAlertActionStyleCancel handler:nil]];
                [self presentViewController:failure animated:YES completion:nil];
                [self.tableView reloadData]; return;
            }
            UIAlertController *waiting = [UIAlertController alertControllerWithTitle:@"Pairing With Trusted Mac"
              message:[self pairingProgressMessage]
              preferredStyle:UIAlertControllerStyleAlert];
            [waiting addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel
              handler:^(UIAlertAction *action) { [self cancelPairing]; }]];
            self.progressAlert = waiting;
            [self presentViewController:waiting animated:YES completion:nil];
        });
      }] resume];
}

- (void)cancelPairing
{
    // Cancellation may race the asynchronous job-creation response.  Keep the
    // intent latched; beginPairing sends the exact-job cancellation as soon as
    // the authenticated bridge returns its UUID.  No Apple trust state is
    // changed by cancelling the 0-Sky operation.
    self.cancellationRequested = YES;
    self.operationActive = NO;
    if(!self.jobID.length) { [self.tableView reloadData]; return; }
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:
        [NSURL URLWithString:@"http://127.0.0.1:48654/v1/pairing/cancel"]];
    request.HTTPMethod = @"POST"; request.timeoutInterval = 10;
    [request setValue:[self bridgeToken] forHTTPHeaderField:@"X-TrollStore-Bridge-Token"];
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    request.HTTPBody = [NSJSONSerialization dataWithJSONObject:@{@"job_id":self.jobID} options:0 error:nil];
    [[NSURLSession.sharedSession dataTaskWithRequest:request completionHandler:
      ^(NSData *data, NSURLResponse *response, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            self.operationActive = NO; self.jobID = nil; self.progressAlert = nil;
            self.cancellationRequested = NO;
            [self refreshStatus];
        });
      }] resume];
}

@end
