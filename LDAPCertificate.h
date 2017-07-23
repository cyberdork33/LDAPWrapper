//
//  LDAPCertificate.h
//  LDAPManager
//
//  Created by cyberdork33@gmail.com on 5/14/12.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>

@interface LDAPCertificate : NSObject

/*!
 @property commonName
 @brief
*/
@property (readonly, copy) NSString *commonName;
/*!
 @property emailAddresses
 @brief
 */
@property (readonly, copy) NSArray *emailAddresses;
/*!
 @property subjectSummary
 @brief
 */
@property (readonly, copy) NSString *subjectSummary;
/*!
 @property userCertificateData
 @brief This is the entry's certificate in an NSData container.
 As is stated in the specification, this SHOULD be a DER-encoded certificate.
 */
@property (strong) NSData *userCertificateData;
/*!
 @property userCertificateRef
 @brief This is the entry's certificate as a SecCertificateRef.
 */
@property (readonly) SecCertificateRef userCertificateRef;

@end
