#import "TSDoodlePatternRecorderViewController.h"
#import <float.h>
#import <math.h>

static NSString* const TSDoodleDomain = @"com.nahtedetihw.doodleprefs";
static NSString* const TSDoodleReload = @"com.nahtedetihw.doodleprefs/ReloadPrefs";

@interface TSDoodleCanvas : UIView
@property(nonatomic,copy) void (^onPath)(NSArray<NSDictionary*>* points);
@property(nonatomic,strong) CAShapeLayer* stroke;
@property(nonatomic,strong) UIBezierPath* current;
@property(nonatomic,strong) NSMutableArray<NSDictionary*>* points;
@end

@implementation TSDoodleCanvas

- (instancetype)initWithFrame:(CGRect)frame
{
    self = [super initWithFrame:frame];
    if(self) {
        self.backgroundColor = UIColor.secondarySystemGroupedBackgroundColor;
        self.layer.cornerRadius = 20;
        self.clipsToBounds = YES;
        _stroke = [CAShapeLayer layer];
        _stroke.fillColor = UIColor.clearColor.CGColor;
        _stroke.strokeColor = UIColor.systemBlueColor.CGColor;
        _stroke.lineWidth = 12;
        _stroke.lineCap = kCALineCapRound;
        _stroke.lineJoin = kCALineJoinRound;
        [self.layer addSublayer:_stroke];
    }
    return self;
}

- (void)layoutSubviews
{
    [super layoutSubviews];
    self.stroke.frame = self.bounds;
}

- (CGPoint)boundedPoint:(UITouch*)touch
{
    CGPoint point = [touch locationInView:self];
    point.x = MIN(MAX(point.x, 0), self.bounds.size.width);
    point.y = MIN(MAX(point.y, 0), self.bounds.size.height);
    return point;
}

- (void)appendPoint:(CGPoint)point
{
    if(self.points.count >= 1024) return;
    NSDictionary* last = self.points.lastObject;
    if(last && hypot(point.x - [last[@"x"] doubleValue],
                     point.y - [last[@"y"] doubleValue]) < 3) return;
    [self.points addObject:@{@"x": @(point.x), @"y": @(point.y)}];
    [self.current addLineToPoint:point];
    self.stroke.path = self.current.CGPath;
}

- (void)touchesBegan:(NSSet<UITouch*>*)touches withEvent:(UIEvent*)event
{
    (void)event;
    UITouch* touch = touches.anyObject;
    if(!touch) return;
    CGPoint point = [self boundedPoint:touch];
    self.points = [NSMutableArray arrayWithObject:@{@"x": @(point.x), @"y": @(point.y)}];
    self.current = [UIBezierPath bezierPath];
    [self.current moveToPoint:point];
    self.stroke.path = self.current.CGPath;
}

- (void)touchesMoved:(NSSet<UITouch*>*)touches withEvent:(UIEvent*)event
{
    (void)event;
    UITouch* touch = touches.anyObject;
    if(touch && self.current) [self appendPoint:[self boundedPoint:touch]];
}

- (void)touchesEnded:(NSSet<UITouch*>*)touches withEvent:(UIEvent*)event
{
    (void)event;
    UITouch* touch = touches.anyObject;
    if(touch && self.current) [self appendPoint:[self boundedPoint:touch]];
    NSArray* completed = self.points.copy;
    self.current = nil;
    self.points = nil;
    if(self.onPath) self.onPath(completed ?: @[]);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.35 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ self.stroke.path = nil; });
}

- (void)touchesCancelled:(NSSet<UITouch*>*)touches withEvent:(UIEvent*)event
{
    (void)touches; (void)event;
    self.current = nil;
    self.points = nil;
    self.stroke.path = nil;
}

@end

@interface TSDoodlePatternRecorderViewController ()
@property(nonatomic,strong) UILabel* status;
@property(nonatomic,strong) TSDoodleCanvas* canvas;
@property(nonatomic,strong) NSMutableArray<NSArray<NSDictionary*>*>* recordings;
@property(nonatomic,strong) NSArray<NSValue*>* referenceSamples;
@property(nonatomic,strong) UIBarButtonItem* saveButton;
@end

@implementation TSDoodlePatternRecorderViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.title = @"Record Doodle";
    self.view.backgroundColor = UIColor.systemGroupedBackgroundColor;
    self.recordings = [NSMutableArray new];
    self.saveButton = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemSave
        target:self action:@selector(savePattern)];
    self.saveButton.enabled = NO;
    self.navigationItem.rightBarButtonItem = self.saveButton;

    UILabel* status = [UILabel new];
    status.translatesAutoresizingMaskIntoConstraints = NO;
    status.textAlignment = NSTextAlignmentCenter;
    status.numberOfLines = 0;
    status.font = [UIFont preferredFontForTextStyle:UIFontTextStyleHeadline];
    self.status = status;
    [self.view addSubview:status];

    TSDoodleCanvas* canvas = [TSDoodleCanvas new];
    canvas.translatesAutoresizingMaskIntoConstraints = NO;
    self.canvas = canvas;
    __weak typeof(self) weakSelf = self;
    canvas.onPath = ^(NSArray<NSDictionary*>* points) {
        [weakSelf acceptPath:points];
    };
    [self.view addSubview:canvas];

    UILabel* explanation = [UILabel new];
    explanation.translatesAutoresizingMaskIntoConstraints = NO;
    explanation.numberOfLines = 0;
    explanation.textAlignment = NSTextAlignmentCenter;
    explanation.textColor = UIColor.secondaryLabelColor;
    explanation.font = [UIFont preferredFontForTextStyle:UIFontTextStyleFootnote];
    explanation.text = @"Draw the same pattern three times. Saving it does not activate Doodle. "
        @"Enable it in Doodle settings after this device passes lock-screen validation.";
    [self.view addSubview:explanation];

    UIButton* restart = [UIButton buttonWithType:UIButtonTypeSystem];
    restart.translatesAutoresizingMaskIntoConstraints = NO;
    [restart setTitle:@"Start Over" forState:UIControlStateNormal];
    [restart addTarget:self action:@selector(startOver) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:restart];

    UILayoutGuide* safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [status.topAnchor constraintEqualToAnchor:safe.topAnchor constant:16],
        [status.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:24],
        [status.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-24],
        [canvas.topAnchor constraintEqualToAnchor:status.bottomAnchor constant:20],
        [canvas.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:16],
        [canvas.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-16],
        [canvas.heightAnchor constraintEqualToConstant:300],
        [explanation.topAnchor constraintEqualToAnchor:canvas.bottomAnchor constant:14],
        [explanation.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:24],
        [explanation.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-24],
        [restart.topAnchor constraintEqualToAnchor:explanation.bottomAnchor constant:12],
        [restart.centerXAnchor constraintEqualToAnchor:safe.centerXAnchor],
        [restart.bottomAnchor constraintLessThanOrEqualToAnchor:safe.bottomAnchor constant:-12],
    ]];
    [self updateStatus];
}

- (void)updateStatus
{
    if(self.recordings.count == 3)
        self.status.text = @"Three matching patterns recorded. Tap Save.";
    else
        self.status.text = [NSString stringWithFormat:@"Draw pattern %lu of 3",
            (unsigned long)(self.recordings.count + 1)];
    self.saveButton.enabled = self.recordings.count == 3;
}

// Normalize by path length and bounding box. This checks that the researcher
// entered the same gesture three times without persisting a sample prematurely.
+ (NSArray<NSValue*>*)normalizedSamples:(NSArray<NSDictionary*>*)raw
{
    if(raw.count < 8 || raw.count > 1024) return nil;
    NSMutableArray<NSValue*>* points = [NSMutableArray arrayWithCapacity:raw.count];
    double minX = DBL_MAX, minY = DBL_MAX, maxX = -DBL_MAX, maxY = -DBL_MAX;
    for(id item in raw) {
        if(![item isKindOfClass:NSDictionary.class] ||
           ![item[@"x"] isKindOfClass:NSNumber.class] ||
           ![item[@"y"] isKindOfClass:NSNumber.class]) return nil;
        double x = [item[@"x"] doubleValue], y = [item[@"y"] doubleValue];
        if(!isfinite(x) || !isfinite(y) || x < 0 || y < 0 || x > 8192 || y > 8192)
            return nil;
        minX = MIN(minX, x); maxX = MAX(maxX, x);
        minY = MIN(minY, y); maxY = MAX(maxY, y);
        [points addObject:[NSValue valueWithCGPoint:CGPointMake(x, y)]];
    }
    double width = maxX - minX, height = maxY - minY;
    if(width < 30 || height < 30) return nil;
    double total = 0;
    NSMutableArray<NSNumber*>* cumulative = [NSMutableArray arrayWithObject:@0];
    for(NSUInteger index = 1; index < points.count; index++) {
        CGPoint a = points[index - 1].CGPointValue, b = points[index].CGPointValue;
        total += hypot(b.x - a.x, b.y - a.y);
        [cumulative addObject:@(total)];
    }
    if(total < 90) return nil;
    double scale = MAX(width, height);
    NSMutableArray<NSValue*>* samples = [NSMutableArray arrayWithCapacity:32];
    NSUInteger segment = 1;
    for(NSUInteger index = 0; index < 32; index++) {
        double target = total * index / 31.0;
        while(segment < cumulative.count - 1 && cumulative[segment].doubleValue < target)
            segment++;
        double low = cumulative[segment - 1].doubleValue;
        double high = cumulative[segment].doubleValue;
        double ratio = high > low ? (target - low) / (high - low) : 0;
        CGPoint a = points[segment - 1].CGPointValue, b = points[segment].CGPointValue;
        [samples addObject:[NSValue valueWithCGPoint:CGPointMake(
            ((a.x + (b.x - a.x) * ratio) - minX) / scale,
            ((a.y + (b.y - a.y) * ratio) - minY) / scale)]];
    }
    return samples.copy;
}

+ (BOOL)samples:(NSArray<NSValue*>*)candidate match:(NSArray<NSValue*>*)reference
{
    if(candidate.count != 32 || reference.count != 32) return NO;
    double distance = 0;
    for(NSUInteger index = 0; index < 32; index++) {
        CGPoint a = candidate[index].CGPointValue, b = reference[index].CGPointValue;
        distance += hypot(a.x - b.x, a.y - b.y);
    }
    return distance / 32.0 < 0.16;
}

- (void)acceptPath:(NSArray<NSDictionary*>*)raw
{
    if(self.recordings.count == 3) return;
    NSArray<NSValue*>* samples = [self.class normalizedSamples:raw];
    if(!samples) {
        self.status.text = @"Draw a longer pattern with turns, then try again.";
        return;
    }
    if(self.referenceSamples && ![self.class samples:samples match:self.referenceSamples]) {
        self.status.text = @"That pattern differs from the first. Try again.";
        return;
    }
    if(!self.referenceSamples) self.referenceSamples = samples;
    [self.recordings addObject:raw];
    [self updateStatus];
}

- (void)startOver
{
    [self.recordings removeAllObjects];
    self.referenceSamples = nil;
    [self updateStatus];
}

- (void)savePattern
{
    if(self.recordings.count != 3) return;
    NSArray* saved = self.recordings.copy;
    NSUserDefaults* defaults = [[NSUserDefaults alloc] initWithSuiteName:TSDoodleDomain];
    [defaults setObject:saved forKey:@"paths"];
    BOOL synchronized = [defaults synchronize];
    NSDictionary* persisted = [[[NSUserDefaults alloc] initWithSuiteName:TSDoodleDomain]
        persistentDomainForName:TSDoodleDomain];
    if(!synchronized || ![persisted[@"paths"] isEqual:saved]) {
        UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Could not save pattern"
            message:@"Doodle preferences are not writable. Check the 0-Sky bootstrap and try again."
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK"
            style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
        return;
    }
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
        (__bridge CFStringRef)TSDoodleReload, NULL, NULL, true);
    [self.navigationController popViewControllerAnimated:YES];
}

@end
