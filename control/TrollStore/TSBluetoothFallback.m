#import "TSBluetoothFallback.h"
#import "TSRootlessPaths.h"

#import <CoreBluetooth/CoreBluetooth.h>
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonHMAC.h>
#import <Security/Security.h>
#import <arpa/inet.h>
#import <errno.h>
#import <sys/socket.h>
#import <unistd.h>

static NSString *const TSBLERXUUID = @"0B5C0002-7B8E-4D6A-9E31-0A5C00000002";
static NSString *const TSBLETXUUID = @"0B5C0003-7B8E-4D6A-9E31-0A5C00000003";
static NSString *const TSBLEEnabledKey = @"0SkyBluetoothFallbackEnabled";

static NSData *TSBLEHMAC(NSData *key, NSString *label, NSData *hostNonce, NSData *deviceNonce)
{
    NSMutableData *message = [NSMutableData dataWithData:[label dataUsingEncoding:NSUTF8StringEncoding]];
    uint8_t zero = 0;
    [message appendBytes:&zero length:1];
    [message appendData:hostNonce ?: NSData.data];
    [message appendData:deviceNonce ?: NSData.data];
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, key.bytes, key.length, message.bytes, message.length, digest);
    return [NSData dataWithBytes:digest length:sizeof(digest)];
}

static BOOL TSBLEConstantEqual(NSData *a, NSData *b)
{
    if(a.length != b.length || a.length == 0) return NO;
    const uint8_t *aa = a.bytes, *bb = b.bytes;
    uint8_t difference = 0;
    for(NSUInteger i = 0; i < a.length; i++) difference |= aa[i] ^ bb[i];
    return difference == 0;
}

static NSString *TSBLEServiceUUIDForToken(NSData *token)
{
    NSMutableData *digest = [TSBLEHMAC(token, @"0sky-ble-service-v1", nil, nil) mutableCopy];
    uint8_t *bytes = digest.mutableBytes;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    return [NSString stringWithFormat:
        @"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        bytes[0],bytes[1],bytes[2],bytes[3],bytes[4],bytes[5],bytes[6],bytes[7],
        bytes[8],bytes[9],bytes[10],bytes[11],bytes[12],bytes[13],bytes[14],bytes[15]];
}

@interface TSBluetoothFallback () <CBPeripheralManagerDelegate>
@property (nonatomic, strong) CBPeripheralManager *manager;
@property (nonatomic, strong) CBMutableCharacteristic *receiveCharacteristic;
@property (nonatomic, strong) CBMutableCharacteristic *transmitCharacteristic;
@property (nonatomic, strong) CBCentral *subscribedCentral;
@property (nonatomic, strong) NSData *token;
@property (nonatomic, copy) NSString *serviceUUID;
@property (nonatomic, strong) NSData *hostNonce;
@property (nonatomic, strong) NSData *deviceNonce;
@property (nonatomic) BOOL authenticated;
@property (nonatomic) BOOL advertising;
@property (nonatomic) int socketFD;
@property (nonatomic, strong) dispatch_queue_t socketQueue;
@property (nonatomic, strong) dispatch_queue_t socketWriteQueue;
@property (nonatomic, strong) NSMutableArray<NSData *> *pendingNotifications;
@property (nonatomic) UIBackgroundTaskIdentifier backgroundTask;
@property (nonatomic, copy) NSString *statusText;
@end

@implementation TSBluetoothFallback

+ (instancetype)sharedFallback
{
    static TSBluetoothFallback *shared;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ shared = [TSBluetoothFallback new]; });
    return shared;
}

- (instancetype)init
{
    self = [super init];
    if(self) {
        _socketFD = -1;
        _socketQueue = dispatch_queue_create("com.liquidsky.0sky.bluetooth.socket", DISPATCH_QUEUE_SERIAL);
        _socketWriteQueue = dispatch_queue_create("com.liquidsky.0sky.bluetooth.socket-write", DISPATCH_QUEUE_SERIAL);
        _pendingNotifications = [NSMutableArray array];
        _backgroundTask = UIBackgroundTaskInvalid;
        _statusText = @"Starting";
    }
    return self;
}

- (NSData *)loadToken
{
    NSString *value = [[[NSString stringWithContentsOfFile:TSRootlessPaths.bridgeTokenPath
        encoding:NSASCIIStringEncoding error:nil]
        stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet] lowercaseString];
    if(value.length != 64) return nil;
    NSCharacterSet *invalid = [[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"] invertedSet];
    if([value rangeOfCharacterFromSet:invalid].location != NSNotFound) return nil;
    return [value dataUsingEncoding:NSASCIIStringEncoding];
}

- (void)start
{
    if([[NSUserDefaults standardUserDefaults] objectForKey:TSBLEEnabledKey] == nil)
        [[NSUserDefaults standardUserDefaults] setBool:YES forKey:TSBLEEnabledKey];
    if(![[NSUserDefaults standardUserDefaults] boolForKey:TSBLEEnabledKey]) {
        self.statusText = @"Disabled";
        return;
    }
    self.token = [self loadToken];
    if(!self.token) {
        self.statusText = @"Bridge token unavailable";
        return;
    }
    self.serviceUUID = TSBLEServiceUUIDForToken(self.token);
    if(!self.manager) {
        NSDictionary *options = @{CBPeripheralManagerOptionRestoreIdentifierKey:
            @"com.liquidsky.CrypStore.bluetooth-fallback"};
        self.manager = [[CBPeripheralManager alloc] initWithDelegate:self
            queue:dispatch_get_main_queue() options:options];
    } else if(self.manager.state == CBManagerStatePoweredOn) {
        [self publishService];
    }
}

- (void)stop
{
    [self.manager stopAdvertising];
    [self.manager removeAllServices];
    self.advertising = NO;
    [self resetSession];
    self.statusText = @"Disabled";
}

- (void)publishService
{
    if(!self.token || self.manager.state != CBManagerStatePoweredOn) return;
    [self.manager stopAdvertising];
    [self.manager removeAllServices];
    CBUUID *rxUUID = [CBUUID UUIDWithString:TSBLERXUUID];
    CBUUID *txUUID = [CBUUID UUIDWithString:TSBLETXUUID];
    self.receiveCharacteristic = [[CBMutableCharacteristic alloc]
        initWithType:rxUUID
        properties:CBCharacteristicPropertyWrite
        value:nil
        permissions:CBAttributePermissionsWriteEncryptionRequired];
    self.transmitCharacteristic = [[CBMutableCharacteristic alloc]
        initWithType:txUUID
        properties:CBCharacteristicPropertyNotify
        value:nil
        permissions:CBAttributePermissionsReadEncryptionRequired];
    CBMutableService *service = [[CBMutableService alloc]
        initWithType:[CBUUID UUIDWithString:self.serviceUUID] primary:YES];
    service.characteristics = @[self.receiveCharacteristic, self.transmitCharacteristic];
    [self.manager addService:service];
}

- (void)peripheralManagerDidUpdateState:(CBPeripheralManager *)peripheral
{
    switch(peripheral.state) {
        case CBManagerStatePoweredOn:
            self.statusText = @"Advertising — paired Mac only";
            [self publishService];
            break;
        case CBManagerStatePoweredOff: self.statusText = @"Bluetooth is off"; break;
        case CBManagerStateUnauthorized: self.statusText = @"Bluetooth permission required"; break;
        case CBManagerStateUnsupported: self.statusText = @"Bluetooth unavailable"; break;
        default: self.statusText = @"Bluetooth starting"; break;
    }
}

- (void)peripheralManager:(CBPeripheralManager *)peripheral didAddService:(CBService *)service error:(NSError *)error
{
    if(error) {
        self.statusText = [NSString stringWithFormat:@"Service error: %@", error.localizedDescription];
        return;
    }
    [peripheral startAdvertising:@{
        CBAdvertisementDataServiceUUIDsKey: @[[CBUUID UUIDWithString:self.serviceUUID]],
        CBAdvertisementDataLocalNameKey: @"0-Sky"
    }];
}

- (void)peripheralManagerDidStartAdvertising:(CBPeripheralManager *)peripheral error:(NSError *)error
{
    self.advertising = error == nil;
    self.statusText = error ? [NSString stringWithFormat:@"Advertising error: %@", error.localizedDescription]
                            : @"Advertising — paired Mac only";
    [[NSNotificationCenter defaultCenter] postNotificationName:@"0SkyBluetoothStatusChanged" object:nil];
}

- (void)peripheralManager:(CBPeripheralManager *)peripheral
    central:(CBCentral *)central didSubscribeToCharacteristic:(CBCharacteristic *)characteristic
{
    if([characteristic.UUID isEqual:self.transmitCharacteristic.UUID]) {
        self.subscribedCentral = central;
        self.statusText = @"Bluetooth Mac connected — authenticating";
    }
}

- (void)peripheralManager:(CBPeripheralManager *)peripheral
    central:(CBCentral *)central didUnsubscribeFromCharacteristic:(CBCharacteristic *)characteristic
{
    if([central.identifier isEqual:self.subscribedCentral.identifier]) [self resetSession];
}

- (void)peripheralManager:(CBPeripheralManager *)peripheral didReceiveWriteRequests:(NSArray<CBATTRequest *> *)requests
{
    for(CBATTRequest *request in requests) {
        CBATTError result = CBATTErrorSuccess;
        if(![request.characteristic.UUID isEqual:self.receiveCharacteristic.UUID] ||
           request.offset != 0 || request.value.length < 1) {
            result = CBATTErrorInvalidPdu;
        } else if(self.subscribedCentral &&
                  ![request.central.identifier isEqual:self.subscribedCentral.identifier]) {
            result = CBATTErrorInsufficientAuthorization;
        } else {
            [self handleFrame:request.value fromCentral:request.central];
        }
        [peripheral respondToRequest:request withResult:result];
    }
}

- (void)handleFrame:(NSData *)frame fromCentral:(CBCentral *)central
{
    const uint8_t *bytes = frame.bytes;
    uint8_t type = bytes[0];
    NSData *payload = [frame subdataWithRange:NSMakeRange(1, frame.length - 1)];
    self.subscribedCentral = central;
    if(type == 0x01 && payload.length == 33 && ((const uint8_t *)payload.bytes)[0] == 1) {
        self.hostNonce = [payload subdataWithRange:NSMakeRange(1, 32)];
        NSMutableData *nonce = [NSMutableData dataWithLength:32];
        if(SecRandomCopyBytes(kSecRandomDefault, nonce.length, nonce.mutableBytes) != errSecSuccess) {
            [self sendControl:0x8f payload:NSData.data];
            return;
        }
        self.deviceNonce = nonce;
        NSData *mac = TSBLEHMAC(self.token, @"0sky-ble-challenge-v1", self.hostNonce, self.deviceNonce);
        NSMutableData *answer = [NSMutableData dataWithData:self.deviceNonce];
        [answer appendData:mac];
        [self sendControl:0x81 payload:answer];
        return;
    }
    if(type == 0x04 && payload.length == 32 && self.hostNonce && self.deviceNonce) {
        NSData *expected = TSBLEHMAC(self.token, @"0sky-ble-auth-v1", self.hostNonce, self.deviceNonce);
        if(!TSBLEConstantEqual(payload, expected)) {
            [self sendControl:0x8e payload:NSData.data];
            [self resetSession];
            return;
        }
        self.authenticated = YES;
        self.statusText = @"Bluetooth fallback authenticated";
        NSData *ready = TSBLEHMAC(self.token, @"0sky-ble-ready-v1", self.hostNonce, self.deviceNonce);
        [self sendControl:0x84 payload:ready];
        [[NSNotificationCenter defaultCenter] postNotificationName:@"0SkyBluetoothStatusChanged" object:nil];
        return;
    }
    if(!self.authenticated) return;
    if(type == 0x05) {
        [self openLocalSSH];
    } else if(type == 0x02 && payload.length) {
        [self writeSocketData:payload];
    } else if(type == 0x03) {
        [self closeSocket];
        [self sendControl:0x83 payload:NSData.data];
    }
}

- (void)openLocalSSH
{
    [self closeSocket];
    if(self.backgroundTask == UIBackgroundTaskInvalid) {
        self.backgroundTask = [UIApplication.sharedApplication beginBackgroundTaskWithName:@"0-Sky Bluetooth SSH"
            expirationHandler:^{ [self closeSocket]; }];
    }
    dispatch_async(self.socketQueue, ^{
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if(fd < 0) { [self notifyOpenStatus:errno]; return; }
        struct sockaddr_in address = {0};
        address.sin_len = sizeof(address);
        address.sin_family = AF_INET;
        address.sin_port = htons(22);
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if(connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
            int code = errno; close(fd); [self notifyOpenStatus:code]; return;
        }
        self.socketFD = fd;
        [self notifyOpenStatus:0];
        uint8_t buffer[4096];
        for(;;) {
            ssize_t count = recv(fd, buffer, sizeof(buffer), 0);
            if(count <= 0) break;
            NSData *data = [NSData dataWithBytes:buffer length:(NSUInteger)count];
            dispatch_async(dispatch_get_main_queue(), ^{ [self sendSocketPayload:data]; });
        }
        if(self.socketFD == fd) self.socketFD = -1;
        close(fd);
        dispatch_async(dispatch_get_main_queue(), ^{ [self sendControl:0x83 payload:NSData.data]; });
    });
}

- (void)notifyOpenStatus:(int)errorCode
{
    uint8_t status[3] = { errorCode == 0 ? 0 : 1,
        (uint8_t)((errorCode >> 8) & 0xff), (uint8_t)(errorCode & 0xff) };
    NSData *payload = [NSData dataWithBytes:status length:sizeof(status)];
    dispatch_async(dispatch_get_main_queue(), ^{ [self sendControl:0x85 payload:payload]; });
}

- (void)writeSocketData:(NSData *)data
{
    // The read loop intentionally occupies socketQueue for the lifetime of the
    // tunnel.  Keep writes on a distinct serial queue so SSH client packets are
    // not starved behind the blocking recv().
    dispatch_async(self.socketWriteQueue, ^{
        int fd = self.socketFD;
        if(fd < 0) return;
        const uint8_t *bytes = data.bytes;
        NSUInteger left = data.length;
        while(left) {
            ssize_t sent = send(fd, bytes, left, MSG_NOSIGNAL);
            if(sent <= 0) { [self closeSocket]; break; }
            bytes += sent; left -= (NSUInteger)sent;
        }
    });
}

- (void)sendSocketPayload:(NSData *)payload
{
    NSUInteger maximum = MAX((NSUInteger)20,
        (NSUInteger)(self.subscribedCentral.maximumUpdateValueLength ?: 20));
    maximum = maximum > 1 ? maximum - 1 : 19;
    for(NSUInteger offset = 0; offset < payload.length; offset += maximum) {
        NSUInteger length = MIN(maximum, payload.length - offset);
        [self sendControl:0x82 payload:[payload subdataWithRange:NSMakeRange(offset, length)]];
    }
}

- (void)sendControl:(uint8_t)type payload:(NSData *)payload
{
    NSMutableData *frame = [NSMutableData dataWithBytes:&type length:1];
    if(payload.length) [frame appendData:payload];
    [self.pendingNotifications addObject:frame];
    [self flushNotifications];
}

- (void)flushNotifications
{
    while(self.pendingNotifications.count && self.subscribedCentral && self.transmitCharacteristic) {
        NSData *frame = self.pendingNotifications.firstObject;
        if(![self.manager updateValue:frame forCharacteristic:self.transmitCharacteristic
                         onSubscribedCentrals:@[self.subscribedCentral]]) return;
        [self.pendingNotifications removeObjectAtIndex:0];
    }
}

- (void)peripheralManagerIsReadyToUpdateSubscribers:(CBPeripheralManager *)peripheral
{
    [self flushNotifications];
}

- (void)closeSocket
{
    int fd = self.socketFD;
    self.socketFD = -1;
    if(fd >= 0) { shutdown(fd, SHUT_RDWR); close(fd); }
    if(self.backgroundTask != UIBackgroundTaskInvalid) {
        [UIApplication.sharedApplication endBackgroundTask:self.backgroundTask];
        self.backgroundTask = UIBackgroundTaskInvalid;
    }
}

- (void)resetSession
{
    [self closeSocket];
    self.authenticated = NO;
    self.hostNonce = nil;
    self.deviceNonce = nil;
    self.subscribedCentral = nil;
    [self.pendingNotifications removeAllObjects];
    if(self.advertising) self.statusText = @"Advertising — paired Mac only";
    [[NSNotificationCenter defaultCenter] postNotificationName:@"0SkyBluetoothStatusChanged" object:nil];
}

- (void)peripheralManager:(CBPeripheralManager *)peripheral willRestoreState:(NSDictionary<NSString *,id> *)dict
{
    NSArray *services = dict[CBPeripheralManagerRestoredStateServicesKey];
    for(CBMutableService *service in services) {
        if([service.UUID isEqual:[CBUUID UUIDWithString:self.serviceUUID]]) {
            for(CBMutableCharacteristic *characteristic in service.characteristics) {
                if([characteristic.UUID isEqual:[CBUUID UUIDWithString:TSBLERXUUID]]) self.receiveCharacteristic = characteristic;
                if([characteristic.UUID isEqual:[CBUUID UUIDWithString:TSBLETXUUID]]) self.transmitCharacteristic = characteristic;
            }
        }
    }
}

@end
