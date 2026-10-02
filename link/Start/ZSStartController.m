#import "ZSStartController.h"
#import "../Theme/ZSLinkTheme.h"

@interface ZSStartController ()
@property (nonatomic, strong) UILabel *titleLabel;
@property (nonatomic, strong) UILabel *subtitleLabel;
@property (nonatomic, strong) UILabel *detailLabel;
@property (nonatomic, strong) UIButton *startButton;
@property (nonatomic, strong) UIButton *themeButton;
@property (nonatomic, assign) BOOL started;
@end

@implementation ZSStartController

- (UILabel *)label:(NSString *)text size:(CGFloat)size weight:(UIFontWeight)weight {
    UILabel *label = [UILabel new];
    label.text = text;
    label.textAlignment = NSTextAlignmentCenter;
    label.textColor = UIColor.whiteColor;
    label.numberOfLines = 0;
    label.font = [UIFont monospacedSystemFontOfSize:size weight:weight];
    label.adjustsFontSizeToFitWidth = YES;
    label.minimumScaleFactor = .7;
    return label;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.titleLabel = [self label:@"0-SKY" size:48 weight:UIFontWeightBold];
    self.subtitleLabel = [self label:@"RESEARCH ENVIRONMENT" size:16 weight:UIFontWeightMedium];
    self.detailLabel = [self label:@"Start the research security console and check the current environment." size:13 weight:UIFontWeightRegular];

    self.startButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [self.startButton setTitle:@"START RESEARCH SECURITY CONSOLE" forState:UIControlStateNormal];
    self.startButton.titleLabel.font = [UIFont monospacedSystemFontOfSize:14 weight:UIFontWeightBold];
    self.startButton.titleLabel.adjustsFontSizeToFitWidth = YES;
    self.startButton.titleLabel.minimumScaleFactor = .68;
    self.startButton.layer.cornerRadius = 12;
    [self.startButton addTarget:self action:@selector(start) forControlEvents:UIControlEventTouchUpInside];
    self.startButton.accessibilityIdentifier = @"startResearchConsole";

    self.themeButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.themeButton.titleLabel.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightMedium];
    [self.themeButton addTarget:self action:@selector(chooseTheme) forControlEvents:UIControlEventTouchUpInside];
    self.themeButton.accessibilityIdentifier = @"chooseTheme";

    UIStackView *stack = [UIStackView new];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.alignment = UIStackViewAlignmentFill;
    stack.spacing = 20;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:stack];
    [stack addArrangedSubview:self.titleLabel];
    [stack addArrangedSubview:self.subtitleLabel];
    UIView *gap = [UIView new];
    [gap.heightAnchor constraintEqualToConstant:24].active = YES;
    [stack addArrangedSubview:gap];
    [stack addArrangedSubview:self.detailLabel];
    UIView *buttonGap = [UIView new];
    [buttonGap.heightAnchor constraintEqualToConstant:12].active = YES;
    [stack addArrangedSubview:buttonGap];
    [stack addArrangedSubview:self.startButton];
    [stack addArrangedSubview:self.themeButton];
    [self.startButton.heightAnchor constraintEqualToConstant:54].active = YES;
    [self.themeButton.heightAnchor constraintEqualToConstant:42].active = YES;
    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [stack.centerYAnchor constraintEqualToAnchor:safe.centerYAnchor],
        [stack.leadingAnchor constraintGreaterThanOrEqualToAnchor:safe.leadingAnchor constant:24],
        [stack.trailingAnchor constraintLessThanOrEqualToAnchor:safe.trailingAnchor constant:-24],
        [stack.centerXAnchor constraintEqualToAnchor:safe.centerXAnchor],
        [stack.widthAnchor constraintLessThanOrEqualToConstant:420]
    ]];
    [self applyTheme];
}

- (BOOL)prefersStatusBarHidden { return YES; }

- (void)applyTheme {
    ZSLinkTheme *theme = [ZSLinkTheme currentTheme];
    self.view.backgroundColor = theme.backgroundColor;
    self.titleLabel.textColor = theme.accentColor;
    self.subtitleLabel.textColor = UIColor.whiteColor;
    self.detailLabel.textColor = [UIColor colorWithWhite:.72 alpha:1];
    self.startButton.backgroundColor = theme.accentColor;
    [self.startButton setTitleColor:UIColor.blackColor forState:UIControlStateNormal];
    [self.themeButton setTitle:[NSString stringWithFormat:@"COLOR THEME: %@  ›", theme.name]
                        forState:UIControlStateNormal];
    [self.themeButton setTitleColor:theme.accentColor forState:UIControlStateNormal];
}

- (void)chooseTheme {
    __weak typeof(self) weakSelf = self;
    [ZSLinkTheme presentPickerFrom:self anchor:self.themeButton onChange:^{ [weakSelf applyTheme]; }];
}

- (void)start {
    if (self.started) return;
    self.started = YES;
    self.startButton.enabled = NO;
    if (self.onStart) self.onStart();
}

@end
