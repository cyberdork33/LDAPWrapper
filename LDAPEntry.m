//
//  LDAPEntry.m
//  LDAPManager
//
//  Created by cyberdork33@gmail.com on 5/14/12.
//

#import "LDAPEntry.h"

@implementation LDAPEntry

@synthesize cn = _cn;
@synthesize mail = _mail;
@synthesize userCertificate = _userCertificate;
@synthesize defaultEmailEntry = _defaultEmailEntry;

- (BOOL)hasCertificate {
    return (self.userCertificate.userCertificateData != nil);
}

- (LDAPEntry *)init {
    if (self = [super init]) {
        self.userCertificate = [[LDAPCertificate alloc] init];
    }
    return self;
}
@end
