//
//  LDAPCertificate.m
//  LDAPManager
//
//  Created by cyberdork33@gmail.com on 5/14/12.
//

#import "LDAPCertificate.h"

@implementation LDAPCertificate

@synthesize userCertificateData = _userCertificateData;

- (SecCertificateRef)userCertificateRef {
    // This is safe because SecCertificateCreateWithData returns NULL if
    // the CFDataRef is not a valid DER-encoded X.509 certificate
    return  SecCertificateCreateWithData(NULL, (__bridge CFDataRef)self.userCertificateData);
}

- (NSString *)subjectSummary {
    // This is safe because SecCertificateCopySubjectSummary returns
    // NULL if the SecCertificateRef is invalid
    return (__bridge_transfer NSString *)SecCertificateCopySubjectSummary(self.userCertificateRef);
}

- (NSString *)commonName {


    if (self.userCertificateData) {
        CFStringRef commonName = NULL;
        OSStatus status  = SecCertificateCopyCommonName(self.userCertificateRef, &commonName);
        if ((status != noErr) || (commonName == NULL)) {
            NSLog(@"Could not retrieve Common Name from certificate.  Error %d", status);
            return nil;
        } else {
            // Transfers ownership. No need to CFRelease.
            return (__bridge_transfer NSString *)commonName;
        }
    } else {
        NSLog(@"Tried to get commonName, but there is no certificate data!");
        return nil;
    }
}

- (NSArray *)emailAddresses {

    if (self.userCertificateData) {
        CFArrayRef emails = NULL;
        OSStatus status  = SecCertificateCopyEmailAddresses(self.userCertificateRef, &emails);
        if ((status != noErr) || (emails == NULL) || (CFArrayGetCount(emails) == 0)) {
            NSLog(@"Could not retrieve email addresses from certificate.  Error %d", status);
            return nil;
        } else {
            // Transfers ownership. No need to CFRelease.
            return (__bridge_transfer NSArray *)emails;
        }
    } else {
        //NSLog(@"Tried to get email, but there is no certificate data!");
        return nil;
    }
}

@end
