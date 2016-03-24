#import "TouchID.h"
#import <LocalAuthentication/LocalAuthentication.h>

@implementation TouchID

- (void) verifyFingerprint:(CDVInvokedUrlCommand*)command {

    NSString *message = [command.arguments objectAtIndex:0];
    NSString *passcodeLabel = [command.arguments objectAtIndex:2];
    BOOL fingerPrintOnly = [[command.arguments objectAtIndex:1] boolValue];
    NSString *callbackId = command.callbackId;

    NSBundle *bundle = [NSBundle mainBundle];
    NSDictionary *info = [bundle infoDictionary];

    if(fingerPrintOnly) {
        LAContext *context = [[LAContext alloc] init];
        context.localizedFallbackTitle = @"";
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics localizedReason:message reply:^(BOOL success, NSError *authenticationError){
            if (success) {
                [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK] callbackId:command.callbackId];
            }
            else {
                [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:authenticationError.localizedDescription] callbackId:callbackId];
                NSLog(@"Fingerprint validation failed: %@.", authenticationError.localizedDescription);
            }
        }];
    } else {
        // this replaces the default 'Enter password' button label
        if ([passcodeLabel length] != 0) {
          LAContext *context = [[LAContext alloc] init];
          context.localizedFallbackTitle = passcodeLabel;
        }

        NSString * keychainItemIdentifier = [info objectForKey:@"CFBundleDisplayName"];
        NSString * keychainItemServiceName = [info objectForKey:@"CFBundleIdentifier"];

        // The content of the password is not important.
        NSData * pwData = [@"pass" dataUsingEncoding:NSUTF8StringEncoding];

        // Create the keychain entry attributes.
        NSMutableDictionary	* attributes = [[NSMutableDictionary alloc] initWithObjectsAndKeys:
                                            (__bridge id)(kSecClassGenericPassword), kSecClass,
                                            keychainItemIdentifier, kSecAttrAccount,
                                            keychainItemServiceName, kSecAttrService, nil];

        CFErrorRef accessControlError = NULL;
        SecAccessControlRef accessControlRef = SecAccessControlCreateWithFlags(
                                                                               kCFAllocatorDefault,
                                                                               kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                                               kSecAccessControlUserPresence,
                                                                               &accessControlError);

        if (accessControlRef == NULL || accessControlError != NULL)
        {
            NSLog(@"Cannot create SecAccessControlRef to store a password with identifier “%@” in the key chain: %@.", keychainItemIdentifier, accessControlError);
            return;
        }

        attributes[(__bridge id)kSecAttrAccessControl] = (__bridge id)accessControlRef;

        // In case this code is executed again and the keychain item already exists we want an error code instead of a fingerprint scan.
        attributes[(__bridge id)kSecUseNoAuthenticationUI] = @YES;
        attributes[(__bridge id)kSecValueData] = pwData;

        CFTypeRef result;
        OSStatus osStatus = SecItemAdd((__bridge CFDictionaryRef)attributes, &result);

        if (osStatus != noErr)
        {
            //NSError * error = [[NSError alloc] initWithDomain:NSOSStatusErrorDomain code:osStatus userInfo:nil];

            //NSLog(@"Adding generic password with identifier “%@” to keychain failed with OSError %d: %@.", keychainItemIdentifier, (int)osStatus, error);
        }

        // Determine a string which the device will display in the fingerprint view explaining the reason for the fingerprint scan.

        // The keychain operation shall be performed by the global queue. Otherwise it might just nothing happen.
        dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^(void) {

            // Create the keychain query attributes using the values from the first part of the code.
            NSMutableDictionary * query = [[NSMutableDictionary alloc] initWithObjectsAndKeys:
                                           (__bridge id)(kSecClassGenericPassword), kSecClass, //kSecClassGenericPassword
                                           keychainItemIdentifier, kSecAttrAccount,
                                           keychainItemServiceName, kSecAttrService,
                                           message, kSecUseOperationPrompt,
                                           nil];

            // Start the query and the fingerprint scan and/or device passcode validation
            CFTypeRef result = nil;
            OSStatus userPresenceStatus = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);

            if (noErr == userPresenceStatus)
            {
                [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK] callbackId:command.callbackId];
            }
            else
            {
                [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsInt:userPresenceStatus] callbackId:callbackId];
            }
        });
    }
}

- (void) isAvailable:(CDVInvokedUrlCommand*)command; {

    if (NSClassFromString(@"LAContext") == NULL) {
        [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR] callbackId:command.callbackId];
        return;
    }

    NSError *error = nil;
    LAContext *laContext = [[LAContext alloc] init];

    if ([laContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]) {
        [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK]
                                    callbackId:command.callbackId];
    } else {
        NSArray *errorKeys = @[@"code", @"localizedDescription"];
        [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:[error dictionaryWithValuesForKeys:errorKeys]]
                                    callbackId:command.callbackId];
    }
}

@end
